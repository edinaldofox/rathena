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
CHARINFO_PER_PAGE = 0x0B72
CHAR_MAKE_OK = 0x0B6F
ZONE_NOTIFY = 0x0AC5
BLOCK_CHARACTER = 0x020D
SECOND_PASSWD_LOGIN = 0x08B9

FIXED_PACKET_LENGTHS = {
    CHAR_REFUSE_ENTER: 3,
    CHAR_REFUSE_MAKE: 3,
    SECOND_PASSWD_LOGIN: 12,
    CHARLIST_NOTIFY: 6,
    CHAR_MAKE_OK: 177,
    ZONE_NOTIFY: 156,
}

VARIABLE_PACKET_LENGTHS = {
    LOGIN_OK,
    LOGIN_REFUSE,
    BLOCK_CHARACTER,
    CHAR_ENTER,
    CHARLIST_INFO,
    CHARINFO_PER_PAGE,
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
        if packet_length < 4:
            raise ValueError(f"invalid variable packet length={packet_length} id=0x{packet_id:04x}")
        body = recv_exact(sock, packet_length - 4)
        return packet_id, header + length_bytes + body
    if packet_id in FIXED_PACKET_LENGTHS:
        packet_length = FIXED_PACKET_LENGTHS[packet_id]
        body = recv_exact(sock, packet_length - 2)
        return packet_id, header + body
    raise ValueError(f"unknown packet id=0x{packet_id:04x}")


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
    if len(packet) < 64:
        raise ValueError(f"login packet too short: {len(packet)}")
    _, packet_length, login_id1, aid, login_id2, _last_ip = struct.unpack_from("<HHIIII", packet, 0)
    sex = packet[46]
    token_end = 47 + 17
    sub = packet[token_end:]
    if packet_length != len(packet) or len(sub) < 160:
        raise ValueError(f"unexpected login packet length={packet_length} actual={len(packet)}")
    ip_raw, port = struct.unpack_from("<IH", sub, 0)
    char_ip = socket.inet_ntoa(struct.pack("!I", ip_raw))
    return {
        "login_id1": login_id1,
        "aid": aid,
        "login_id2": login_id2,
        "sex": sex,
        "char_port": port,
        "char_ip": char_ip,
    }


def parse_login(sock: socket.socket) -> dict[str, int]:
    packet_id, packet = recv_packet(sock)
    if packet_id == LOGIN_REFUSE:
        error = struct.unpack_from("<I", packet, 2)[0]
        raise RuntimeError(f"login refused error={error}")
    if packet_id != LOGIN_OK:
        raise RuntimeError(f"unexpected login response id=0x{packet_id:04x}")
    return parse_login_ok(packet)


def connect_char_server(host: str, port: int, aid: int, login_id1: int, login_id2: int, sex: int, timeout: float) -> socket.socket:
    sock = socket.socket()
    sock.settimeout(timeout)
    sock.connect((host, port))
    packet = struct.pack("<HIIIH B", CHAR_CONNECT, aid, login_id1, login_id2, 0, sex)
    sock.sendall(packet)
    echoed_aid = struct.unpack("<I", recv_exact(sock, 4))[0]
    if echoed_aid != aid:
        raise RuntimeError(f"char connect echo mismatch aid={echoed_aid} expected={aid}")
    return sock


def wait_for_initial_char_packets(sock: socket.socket, timeout: float) -> list[int]:
    end = time.time() + timeout
    seen = []
    got_enter = False
    while time.time() < end:
        packet_id, _packet = recv_packet(sock)
        seen.append(packet_id)
        if packet_id == CHAR_ENTER:
            got_enter = True
        if packet_id == CHAR_REFUSE_ENTER:
            raise RuntimeError("char server refused enter")
        if got_enter and packet_id == CHARLIST_NOTIFY:
            return seen
    raise TimeoutError(f"timeout waiting initial char packets, seen={format_packet_ids(seen)}")


def recv_until_packet(sock: socket.socket, expected_ids: set[int], timeout: float, fatal_ids: set[int] | None = None) -> tuple[int, bytes]:
    end = time.time() + timeout
    while time.time() < end:
        packet_id, packet = recv_packet(sock)
        if fatal_ids and packet_id in fatal_ids:
            return packet_id, packet
        if packet_id in expected_ids:
            return packet_id, packet
    raise TimeoutError(f"timeout waiting packets={format_packet_ids(sorted(expected_ids))}")


def create_char(sock: socket.socket, name: str, slot: int, sex: int, timeout: float) -> int:
    packet = struct.pack(
        "<H24sBHHIB",
        CHAR_MAKE,
        name.encode("ascii", "ignore")[:24].ljust(24, b"\0"),
        slot,
        0,
        0,
        0,
        sex,
    )
    sock.sendall(packet)
    packet_id, packet = recv_until_packet(sock, {CHAR_MAKE_OK}, timeout, {CHAR_REFUSE_MAKE})
    if packet_id == CHAR_REFUSE_MAKE:
        raise RuntimeError(f"character creation refused error={packet[2]}")
    if packet_id != CHAR_MAKE_OK:
        raise RuntimeError(f"unexpected character creation response id=0x{packet_id:04x}")
    return packet[140]


def select_char(sock: socket.socket, slot: int, timeout: float) -> tuple[str, int]:
    sock.sendall(struct.pack("<HB", CHAR_SELECT, slot))
    packet_id, packet = recv_until_packet(sock, {ZONE_NOTIFY}, timeout, {CHAR_REFUSE_ENTER})
    if packet_id == CHAR_REFUSE_ENTER:
        raise RuntimeError(f"character select refused error={packet[2]}")
    if packet_id != ZONE_NOTIFY:
        raise RuntimeError(f"unexpected character select response id=0x{packet_id:04x}")
    map_name = packet[6:22].split(b"\0", 1)[0].decode("ascii", "ignore")
    port = struct.unpack_from("<H", packet, 26)[0]
    return map_name, port


def format_packet_ids(packet_ids: list[int]) -> str:
    return ",".join(f"0x{packet_id:04x}" for packet_id in packet_ids)


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe rAthena login/char flow with account login, character creation and selection.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--login-port", type=int, default=6900)
    parser.add_argument("--char-port", type=int, default=6121)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--char-name", required=True)
    parser.add_argument("--slot", type=int, default=0)
    parser.add_argument("--skip-select", action="store_true")
    parser.add_argument("--version", type=int, default=0)
    parser.add_argument("--clienttype", type=int, default=0)
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()

    login_sock = socket.socket()
    login_sock.settimeout(args.timeout)

    try:
        login_sock.connect((args.host, args.login_port))
        login_sock.sendall(build_login_packet(args.username, args.password, args.version, args.clienttype))
        auth = parse_login(login_sock)
    except Exception as exc:
        print(f"probe_error=login:{exc}", file=sys.stderr)
        return 2
    finally:
        login_sock.close()

    char_host = args.host
    char_port = auth["char_port"] or args.char_port

    try:
        char_sock = connect_char_server(
            char_host,
            char_port,
            auth["aid"],
            auth["login_id1"],
            auth["login_id2"],
            auth["sex"],
            args.timeout,
        )
        seen = wait_for_initial_char_packets(char_sock, args.timeout)
        created_slot = create_char(char_sock, args.char_name, args.slot, auth["sex"], args.timeout)
        if args.skip_select:
            map_name, map_port = "", 0
        else:
            map_name, map_port = select_char(char_sock, created_slot, args.timeout)
    except Exception as exc:
        print(f"probe_error=char:{exc}", file=sys.stderr)
        return 3
    finally:
        try:
            char_sock.close()
        except Exception:
            pass

    print(f"aid={auth['aid']}")
    print(f"char_packets={format_packet_ids(seen)}")
    print(f"created_char_slot={created_slot}")
    if not args.skip_select:
        print(f"selected_map={map_name}")
        print(f"selected_map_port={map_port}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
