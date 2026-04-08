#!/usr/bin/env python3

import argparse
import socket
import struct
import sys
import time


LOGIN_OK = 0x0AC4
LOGIN_REFUSE = 0x083E
CHAR_CONNECT = 0x0065
CHAR_SELECT = 0x0066
CHAR_MAKE = 0x0A39
CHAR_ENTER = 0x006B
CHAR_REFUSE_ENTER = 0x006C
CHAR_REFUSE_MAKE = 0x006E
CHARLIST_INFO = 0x082D
CHARLIST_NOTIFY = 0x09A0
CHAR_MAKE_OK = 0x0B6F
ZONE_NOTIFY = 0x0AC5
BLOCK_CHARACTER = 0x020D
SECOND_PASSWD_LOGIN = 0x08B9

MAP_LOGIN = 0x0436
MAP_ACCEPT_ENTER = 0x02EB
MAP_REFUSE_ENTER = 0x0074
MAP_NOTIFY_BAN = 0x0081
MAP_LOAD_END_ACK = 0x007D
MAP_WALK = 0x035F
MAP_AUX_0283 = 0x0283
MAP_EXTEND_BODYITEM_SIZE = 0x0B18
MAP_QUIT = 0x018A

FIXED_PACKET_LENGTHS = {
    BLOCK_CHARACTER: None,
    SECOND_PASSWD_LOGIN: 12,
    MAP_AUX_0283: 6,
    MAP_EXTEND_BODYITEM_SIZE: 4,
    CHAR_REFUSE_ENTER: 3,
    CHAR_REFUSE_MAKE: 3,
    CHARLIST_NOTIFY: 6,
    CHAR_MAKE_OK: 177,
    ZONE_NOTIFY: 156,
    MAP_ACCEPT_ENTER: 13,
    MAP_REFUSE_ENTER: 3,
    MAP_NOTIFY_BAN: 3,
}

VARIABLE_PACKET_LENGTHS = {
    LOGIN_OK,
    LOGIN_REFUSE,
    CHAR_ENTER,
    CHARLIST_INFO,
}


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError(f"socket closed while waiting for {size} bytes")
        data.extend(chunk)
    return bytes(data)


def recv_packet(sock: socket.socket) -> tuple[int, bytes]:
    header = recv_exact(sock, 2)
    packet_id = struct.unpack("<H", header)[0]
    if packet_id in VARIABLE_PACKET_LENGTHS:
        length_bytes = recv_exact(sock, 2)
        packet_length = struct.unpack("<H", length_bytes)[0]
        body = recv_exact(sock, packet_length - 4)
        return packet_id, header + length_bytes + body
    if packet_id == BLOCK_CHARACTER:
        length_bytes = recv_exact(sock, 2)
        packet_length = struct.unpack("<H", length_bytes)[0]
        body = recv_exact(sock, packet_length - 4)
        return packet_id, header + length_bytes + body
    packet_length = FIXED_PACKET_LENGTHS.get(packet_id)
    if packet_length is None:
        raise ValueError(f"unknown packet id=0x{packet_id:04x}")
    body = recv_exact(sock, packet_length - 2)
    return packet_id, header + body


def recv_until(sock: socket.socket, expected_ids: set[int], timeout: float, fatal_ids: set[int] | None = None) -> tuple[int, bytes]:
    end = time.time() + timeout
    while time.time() < end:
        packet_id, packet = recv_packet(sock)
        if fatal_ids and packet_id in fatal_ids:
            return packet_id, packet
        if packet_id in expected_ids:
            return packet_id, packet
    raise TimeoutError(f"timeout waiting packets={','.join(hex(x) for x in sorted(expected_ids))}")


def build_login_packet(username: str, password: str, version: int, clienttype: int) -> bytes:
    return struct.pack(
        "<HI24s24sB",
        0x64,
        version,
        username.encode("ascii", "ignore")[:24].ljust(24, b"\0"),
        password.encode("ascii", "ignore")[:24].ljust(24, b"\0"),
        clienttype,
    )


def parse_login_ok(packet: bytes) -> dict[str, int]:
    _, packet_length, login_id1, aid, login_id2, _last_ip = struct.unpack_from("<HHIIII", packet, 0)
    sex = packet[46]
    sub = packet[64:]
    if packet_length != len(packet) or len(sub) < 160:
        raise ValueError(f"unexpected login packet length={packet_length} actual={len(packet)}")
    _char_ip_raw, char_port = struct.unpack_from("<IH", sub, 0)
    return {
        "login_id1": login_id1,
        "aid": aid,
        "login_id2": login_id2,
        "sex": sex,
        "char_port": char_port,
    }


def parse_zone_notify(packet: bytes) -> tuple[int, str, int]:
    char_id = struct.unpack_from("<I", packet, 2)[0]
    map_name = packet[6:22].split(b"\0", 1)[0].decode("ascii", "ignore")
    map_port = struct.unpack_from("<H", packet, 26)[0]
    return char_id, map_name, map_port


def pack_pos(x: int, y: int, direction: int = 0) -> bytes:
    return bytes([
        (x >> 2) & 0xFF,
        ((x << 6) | ((y >> 4) & 0x3F)) & 0xFF,
        ((y << 4) | (direction & 0x0F)) & 0xFF,
    ])


def unpack_pos(data: bytes) -> tuple[int, int, int]:
    x = ((data[0] & 0xFF) << 2) | (data[1] >> 6)
    y = ((data[1] & 0x3F) << 4) | (data[2] >> 4)
    direction = data[2] & 0x0F
    return x, y, direction


def login_and_select(host: str, login_port: int, char_port: int, username: str, password: str, char_name: str, slot: int, version: int, clienttype: int, timeout: float) -> tuple[dict[str, int], int, str, int]:
    login_sock = socket.socket()
    login_sock.settimeout(timeout)
    login_sock.connect((host, login_port))
    login_sock.sendall(build_login_packet(username, password, version, clienttype))
    packet_id, packet = recv_packet(login_sock)
    login_sock.close()
    if packet_id == LOGIN_REFUSE:
        raise RuntimeError("login refused")
    auth = parse_login_ok(packet)

    char_sock = socket.socket()
    char_sock.settimeout(timeout)
    char_sock.connect((host, auth["char_port"] or char_port))
    char_sock.sendall(struct.pack("<HIIIH B", CHAR_CONNECT, auth["aid"], auth["login_id1"], auth["login_id2"], 0, auth["sex"]))
    recv_exact(char_sock, 4)

    got_enter = False
    while True:
        packet_id, _ = recv_packet(char_sock)
        if packet_id == CHAR_ENTER:
            got_enter = True
        if packet_id == CHAR_REFUSE_ENTER:
            raise RuntimeError("char enter refused")
        if got_enter and packet_id == CHARLIST_NOTIFY:
            break

    char_sock.sendall(
        struct.pack(
            "<H24sBHHIB",
            CHAR_MAKE,
            char_name.encode("ascii", "ignore")[:24].ljust(24, b"\0"),
            slot,
            0,
            0,
            0,
            auth["sex"],
        )
    )
    packet_id, packet = recv_until(char_sock, {CHAR_MAKE_OK}, timeout, {CHAR_REFUSE_MAKE})
    if packet_id == CHAR_REFUSE_MAKE:
        raise RuntimeError(f"character creation refused error={packet[2]}")

    char_sock.sendall(struct.pack("<HB", CHAR_SELECT, slot))
    packet_id, packet = recv_until(char_sock, {ZONE_NOTIFY}, timeout, {CHAR_REFUSE_ENTER})
    char_sock.close()
    if packet_id == CHAR_REFUSE_ENTER:
        raise RuntimeError(f"character select refused error={packet[2]}")
    char_id, map_name, map_port = parse_zone_notify(packet)
    return auth, char_id, map_name, map_port


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe rAthena map-server with login, char select and one movement request.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--login-port", type=int, default=6900)
    parser.add_argument("--char-port", type=int, default=6121)
    parser.add_argument("--map-port", type=int, default=5121)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--char-name", required=True)
    parser.add_argument("--slot", type=int, default=0)
    parser.add_argument("--version", type=int, default=0)
    parser.add_argument("--clienttype", type=int, default=0)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--move-dx", type=int, default=1)
    parser.add_argument("--move-dy", type=int, default=0)
    parser.add_argument("--settle-seconds", type=float, default=1.0)
    args = parser.parse_args()

    try:
        auth, char_id, map_name, map_port = login_and_select(
            args.host,
            args.login_port,
            args.char_port,
            args.username,
            args.password,
            args.char_name,
            args.slot,
            args.version,
            args.clienttype,
            args.timeout,
        )
    except Exception as exc:
        print(f"probe_error=pre_map:{exc}", file=sys.stderr)
        return 2

    map_sock = socket.socket()
    map_sock.settimeout(args.timeout)
    try:
        map_sock.connect((args.host, map_port or args.map_port))
        map_sock.sendall(
            struct.pack(
                "<HIIIIBI",
                MAP_LOGIN,
                auth["aid"],
                char_id,
                auth["login_id1"],
                int(time.time()) & 0xFFFFFFFF,
                auth["sex"],
                0,
            )
        )
        packet_id, packet = recv_until(map_sock, {MAP_ACCEPT_ENTER}, args.timeout, {MAP_REFUSE_ENTER})
        if packet_id == MAP_REFUSE_ENTER:
            raise RuntimeError(f"map enter refused error={packet[2]}")

        x, y, direction = unpack_pos(packet[6:9])
        map_sock.sendall(struct.pack("<H", MAP_LOAD_END_ACK))
        time.sleep(0.2)
        target_x = x + args.move_dx
        target_y = y + args.move_dy
        map_sock.sendall(struct.pack("<H3s", MAP_WALK, pack_pos(target_x, target_y, direction)))
        time.sleep(args.settle_seconds)
        map_sock.sendall(struct.pack("<HH", MAP_QUIT, 0))
        time.sleep(0.5)
    except Exception as exc:
        print(f"probe_error=map:{exc}", file=sys.stderr)
        return 3
    finally:
        map_sock.close()

    print(f"aid={auth['aid']}")
    print(f"char_id={char_id}")
    print(f"map_name={map_name}")
    print(f"start_x={x}")
    print(f"start_y={y}")
    print(f"target_x={target_x}")
    print(f"target_y={target_y}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
