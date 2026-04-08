#!/usr/bin/env python3

import argparse
import socket
import struct
import sys
import time
import traceback


LOGIN_OK = 0x0AC4
LOGIN_REFUSE = 0x083E
CHAR_CONNECT = 0x0065
CHAR_SELECT = 0x0066
CHAR_ENTER = 0x006B
CHAR_REFUSE_ENTER = 0x006C
CHARLIST_INFO = 0x082D
CHARLIST_NOTIFY = 0x09A0
ZONE_NOTIFY = 0x0AC5
BLOCK_CHARACTER = 0x020D
SECOND_PASSWD_LOGIN = 0x08B9

MAP_LOGIN = 0x0436
MAP_ACCEPT_ENTER = 0x02EB
MAP_REFUSE_ENTER = 0x0074
MAP_LOAD_END_ACK = 0x007D
MAP_NOTIFY_BAN = 0x0081
MAP_STOPMOVE = 0x0088
MAP_CHANGEMAP = 0x0091
MAP_MESSAGE = 0x008E
MAP_COUPLESTATUS = 0x0141
MAP_ATTACK_RANGE = 0x013A
MAP_FRIENDS_LIST = 0x0201
MAP_UNREAD_MAIL = 0x09E7
MAP_BROADCAST2 = 0x01C3
MAP_AUX_0283 = 0x0283
MAP_EXTEND_BODYITEM_SIZE = 0x0B18
MAP_QUIT = 0x018A

TRADE_REQUEST = 0x00E4
TRADE_ACK = 0x00E6
TRADE_ADD_ITEM = 0x00E8
TRADE_OK = 0x00EB
TRADE_CANCEL = 0x00ED
TRADE_COMMIT = 0x00EF

ZC_REQ_EXCHANGE_ITEM = 0x01F4
ZC_REQ_EXCHANGE_ITEM_SHORT = 0x009A
ZC_ACK_EXCHANGE_ITEM = 0x01F5
ZC_ACK_EXCHANGE_ITEM_SHORT = 0x00E7
ZC_ADD_EXCHANGE_ITEM = 0x080F
ZC_ACK_ADD_EXCHANGE_ITEM = 0x00EA
ZC_CONCLUDE_EXCHANGE_ITEM = 0x00EC
ZC_CANCEL_EXCHANGE_ITEM = 0x00EE
ZC_EXEC_EXCHANGE_ITEM = 0x00F0
ZC_PAR_CHANGE = 0x00B0

VARIABLE_PACKET_LENGTHS = {
    LOGIN_OK,
    LOGIN_REFUSE,
    CHAR_ENTER,
    BLOCK_CHARACTER,
    MAP_MESSAGE,
    MAP_BROADCAST2,
    MAP_FRIENDS_LIST,
}

FIXED_PACKET_LENGTHS = {
    SECOND_PASSWD_LOGIN: 12,
    CHARLIST_INFO: 29,
    CHAR_REFUSE_ENTER: 3,
    CHARLIST_NOTIFY: 6,
    ZONE_NOTIFY: 156,
    MAP_ACCEPT_ENTER: 13,
    MAP_REFUSE_ENTER: 3,
    MAP_NOTIFY_BAN: 3,
    MAP_STOPMOVE: 10,
    MAP_CHANGEMAP: 22,
    MAP_COUPLESTATUS: 14,
    MAP_ATTACK_RANGE: 4,
    MAP_AUX_0283: 6,
    MAP_EXTEND_BODYITEM_SIZE: 4,
    MAP_UNREAD_MAIL: 3,
    ZC_REQ_EXCHANGE_ITEM: 33,
    ZC_REQ_EXCHANGE_ITEM_SHORT: 26,
    ZC_ACK_EXCHANGE_ITEM: 9,
    ZC_ACK_EXCHANGE_ITEM_SHORT: 3,
    ZC_ACK_ADD_EXCHANGE_ITEM: 5,
    ZC_CONCLUDE_EXCHANGE_ITEM: 3,
    ZC_CANCEL_EXCHANGE_ITEM: 2,
    ZC_EXEC_EXCHANGE_ITEM: 3,
    ZC_PAR_CHANGE: 8,
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
    packet_length = FIXED_PACKET_LENGTHS.get(packet_id)
    if packet_length is None:
        raise ValueError(f"unknown packet id=0x{packet_id:04x}")
    body = recv_exact(sock, packet_length - 2)
    return packet_id, header + body


def recv_until(sock: socket.socket, expected_ids: set[int], timeout: float) -> tuple[int, bytes]:
    end = time.time() + timeout
    while time.time() < end:
        packet_id, packet = recv_packet(sock)
        if packet_id in expected_ids:
            return packet_id, packet
    raise TimeoutError(f"timeout waiting packets={','.join(hex(x) for x in sorted(expected_ids))}")


def recv_packet_nonblocking(sock: socket.socket) -> tuple[int, bytes] | None:
    sock.setblocking(False)
    try:
        try:
            return recv_packet(sock)
        except BlockingIOError:
            return None
    finally:
        sock.setblocking(True)


def drain(sock: socket.socket, seconds: float) -> list[int]:
    seen: list[int] = []
    end = time.time() + seconds
    while time.time() < end:
        packet = recv_packet_nonblocking(sock)
        if packet is None:
            time.sleep(0.05)
            continue
        seen.append(packet[0])
    return seen


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


def parse_zone_notify(packet: bytes) -> tuple[int, int]:
    char_id = struct.unpack_from("<I", packet, 2)[0]
    map_port = struct.unpack_from("<H", packet, 26)[0]
    return char_id, map_port


def login_select_map(host: str, login_port: int, char_port: int, map_port: int, username: str, password: str, slot: int, version: int, clienttype: int, timeout: float) -> tuple[dict[str, int], int, socket.socket]:
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

    char_sock.sendall(struct.pack("<HB", CHAR_SELECT, slot))
    packet_id, packet = recv_until(char_sock, {ZONE_NOTIFY}, timeout)
    char_sock.close()
    char_id, resolved_map_port = parse_zone_notify(packet)

    map_sock = socket.socket()
    map_sock.settimeout(timeout)
    map_sock.connect((host, resolved_map_port or map_port))
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
    packet_id, packet = recv_until(map_sock, {MAP_ACCEPT_ENTER}, timeout)
    if packet_id == MAP_REFUSE_ENTER:
        raise RuntimeError(f"map enter refused error={packet[2]}")
    map_sock.sendall(struct.pack("<H", MAP_LOAD_END_ACK))
    return auth, char_id, map_sock


def wait_trade_request(sock: socket.socket, timeout: float) -> tuple[int, bytes]:
    return recv_until(sock, {ZC_REQ_EXCHANGE_ITEM, ZC_REQ_EXCHANGE_ITEM_SHORT}, timeout)


def wait_trade_ack(sock: socket.socket, timeout: float) -> tuple[int, int]:
    packet_id, packet = recv_until(sock, {ZC_ACK_EXCHANGE_ITEM, ZC_ACK_EXCHANGE_ITEM_SHORT}, timeout)
    if packet_id == ZC_ACK_EXCHANGE_ITEM_SHORT:
        return packet[2], 0
    return packet[2], struct.unpack_from("<I", packet, 3)[0]


def wait_add_ack(sock: socket.socket, timeout: float) -> tuple[int, int]:
    _, packet = recv_until(sock, {ZC_ACK_ADD_EXCHANGE_ITEM}, timeout)
    return struct.unpack_from("<H", packet, 2)[0], packet[4]


def wait_exec(sock: socket.socket, timeout: float) -> int:
    _, packet = recv_until(sock, {ZC_EXEC_EXCHANGE_ITEM}, timeout)
    return packet[2]


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe rAthena player trade between two loaded sessions.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--login-port", type=int, default=6900)
    parser.add_argument("--char-port", type=int, default=6121)
    parser.add_argument("--map-port", type=int, default=5121)
    parser.add_argument("--attacker-user", required=True)
    parser.add_argument("--attacker-pass", required=True)
    parser.add_argument("--victim-user", required=True)
    parser.add_argument("--victim-pass", required=True)
    parser.add_argument("--slot", type=int, default=0)
    parser.add_argument("--version", type=int, default=0)
    parser.add_argument("--clienttype", type=int, default=0)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--trade-index", type=int, required=True, help="client inventory index to trade")
    parser.add_argument("--trade-amount", type=int, default=1)
    args = parser.parse_args()

    try:
        victim_auth, victim_char_id, victim_sock = login_select_map(
            args.host, args.login_port, args.char_port, args.map_port,
            args.victim_user, args.victim_pass, args.slot, args.version, args.clienttype, args.timeout
        )
        attacker_auth, attacker_char_id, attacker_sock = login_select_map(
            args.host, args.login_port, args.char_port, args.map_port,
            args.attacker_user, args.attacker_pass, args.slot, args.version, args.clienttype, args.timeout
        )

        time.sleep(0.2)

        attacker_sock.sendall(struct.pack("<HI", TRADE_REQUEST, victim_auth["aid"]))
        wait_trade_request(victim_sock, args.timeout)

        victim_sock.sendall(struct.pack("<HB", TRADE_ACK, 3))
        attacker_ack_result, _ = wait_trade_ack(attacker_sock, args.timeout)
        victim_ack_result, _ = wait_trade_ack(victim_sock, args.timeout)

        attacker_sock.sendall(struct.pack("<HHI", TRADE_ADD_ITEM, args.trade-index, args.trade_amount))
        add_index, add_result = wait_add_ack(attacker_sock, args.timeout)

        drain(victim_sock, 0.5)
        attacker_sock.sendall(struct.pack("<H", TRADE_OK))
        victim_sock.sendall(struct.pack("<H", TRADE_OK))
        recv_until(attacker_sock, {ZC_CONCLUDE_EXCHANGE_ITEM}, args.timeout)
        recv_until(victim_sock, {ZC_CONCLUDE_EXCHANGE_ITEM}, args.timeout)
        recv_until(attacker_sock, {ZC_CONCLUDE_EXCHANGE_ITEM}, args.timeout)
        recv_until(victim_sock, {ZC_CONCLUDE_EXCHANGE_ITEM}, args.timeout)

        attacker_sock.sendall(struct.pack("<H", TRADE_COMMIT))
        victim_sock.sendall(struct.pack("<H", TRADE_COMMIT))
        attacker_exec = wait_exec(attacker_sock, args.timeout)
        victim_exec = wait_exec(victim_sock, args.timeout)

        attacker_sock.sendall(struct.pack("<HH", MAP_QUIT, 0))
        victim_sock.sendall(struct.pack("<HH", MAP_QUIT, 0))
        time.sleep(0.5)
    except Exception as exc:
        print(f"probe_error={exc}", file=sys.stderr)
        traceback.print_exc()
        return 2
    finally:
        for name in ("attacker_sock", "victim_sock"):
            sock = locals().get(name)
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    print(f"attacker_aid={attacker_auth['aid']}")
    print(f"attacker_char_id={attacker_char_id}")
    print(f"victim_aid={victim_auth['aid']}")
    print(f"victim_char_id={victim_char_id}")
    print(f"trade_ack_attacker={attacker_ack_result}")
    print(f"trade_ack_victim={victim_ack_result}")
    print(f"trade_add_index={add_index}")
    print(f"trade_add_result={add_result}")
    print(f"trade_exec_attacker={attacker_exec}")
    print(f"trade_exec_victim={victim_exec}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
