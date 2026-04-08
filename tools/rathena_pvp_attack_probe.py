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
CHARLIST_INFO = 0x082D
CHAR_ENTER = 0x006B
CHAR_REFUSE_ENTER = 0x006C
CHARLIST_NOTIFY = 0x09A0
ZONE_NOTIFY = 0x0AC5
BLOCK_CHARACTER = 0x020D
SECOND_PASSWD_LOGIN = 0x08B9

MAP_LOGIN = 0x0436
MAP_ACCEPT_ENTER = 0x02EB
MAP_REFUSE_ENTER = 0x0074
MAP_NOTIFY_BAN = 0x0081
MAP_STOPMOVE = 0x0088
MAP_AUX_0283 = 0x0283
MAP_EXTEND_BODYITEM_SIZE = 0x0B18
MAP_BROADCAST2 = 0x01C3
MAP_LOAD_END_ACK = 0x007D
MAP_ACTION = 0x0437
MAP_DAMAGE = 0x08C8
MAP_ATTACK_FAILURE_DISTANCE = 0x0139
MAP_QUIT = 0x018A

VARIABLE_PACKET_LENGTHS = {
    LOGIN_OK,
    LOGIN_REFUSE,
    CHAR_ENTER,
    BLOCK_CHARACTER,
    MAP_BROADCAST2,
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
    MAP_AUX_0283: 6,
    MAP_EXTEND_BODYITEM_SIZE: 4,
    MAP_DAMAGE: 34,
    MAP_ATTACK_FAILURE_DISTANCE: 16,
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
    if packet_length != len(packet):
        raise ValueError(f"unexpected login packet length={packet_length} actual={len(packet)}")
    return {
        "login_id1": login_id1,
        "aid": aid,
        "login_id2": login_id2,
        "sex": sex,
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
    char_sock.connect((host, char_port))
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
    packet_id, packet = recv_until(char_sock, {ZONE_NOTIFY}, timeout, {CHAR_REFUSE_ENTER})
    char_sock.close()
    if packet_id == CHAR_REFUSE_ENTER:
        raise RuntimeError(f"character select refused error={packet[2]}")
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
    packet_id, packet = recv_until(map_sock, {MAP_ACCEPT_ENTER}, timeout, {MAP_REFUSE_ENTER})
    if packet_id == MAP_REFUSE_ENTER:
        raise RuntimeError(f"map enter refused error={packet[2]}")
    map_sock.sendall(struct.pack("<H", MAP_LOAD_END_ACK))
    return auth, char_id, map_sock


def drain_socket(sock: socket.socket, duration: float) -> None:
    end = time.time() + duration
    sock.setblocking(False)
    try:
        while time.time() < end:
            try:
                data = sock.recv(65535)
                if not data:
                    break
            except BlockingIOError:
                time.sleep(0.05)
    finally:
        sock.setblocking(True)


def recv_packet_nonblocking(sock: socket.socket) -> tuple[int, bytes] | None:
    sock.setblocking(False)
    try:
        try:
            return recv_packet(sock)
        except BlockingIOError:
            return None
    finally:
        sock.setblocking(True)


def collect_attack_results(sock: socket.socket, duration: float) -> dict[str, int]:
    summary = {
        "damage_packets": 0,
        "damage_total": 0,
        "last_damage": 0,
        "attack_failures": 0,
        "other_packets": 0,
    }
    end = time.time() + duration
    while time.time() < end:
        packet = recv_packet_nonblocking(sock)
        if packet is None:
            time.sleep(0.05)
            continue

        packet_id, raw = packet
        if packet_id == MAP_DAMAGE:
            damage = struct.unpack_from("<i", raw, 22)[0]
            summary["damage_packets"] += 1
            summary["damage_total"] += damage
            summary["last_damage"] = damage
        elif packet_id == MAP_ATTACK_FAILURE_DISTANCE:
            summary["attack_failures"] += 1
        else:
            summary["other_packets"] += 1
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe rAthena PvP basic attack with two loaded sessions.")
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
    parser.add_argument("--drain-seconds", type=float, default=1.0)
    parser.add_argument("--attack-seconds", type=float, default=2.0)
    parser.add_argument("--result-seconds", type=float, default=1.5)
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

        drain_socket(victim_sock, args.drain_seconds)
        drain_socket(attacker_sock, args.drain_seconds)

        attack_targets = (
            ("victim_aid", victim_auth["aid"]),
            ("victim_char_id", victim_char_id),
        )
        attack_actions = (0, 7)
        attack_attempts: list[str] = []
        for target_label, target_id in attack_targets:
            for action_type in attack_actions:
                attack_attempts.append(f"{target_label}:{action_type}")
                attack_packet = struct.pack("<HIB", MAP_ACTION, target_id, action_type)
                end = time.time() + args.attack_seconds
                while time.time() < end:
                    attacker_sock.sendall(attack_packet)
                    time.sleep(0.2)

        victim_result = collect_attack_results(victim_sock, args.result_seconds)
        attacker_result = collect_attack_results(attacker_sock, args.result_seconds)
        attacker_sock.sendall(struct.pack("<HH", MAP_QUIT, 0))
        victim_sock.sendall(struct.pack("<HH", MAP_QUIT, 0))
        time.sleep(0.5)
    except Exception as exc:
        print(f"probe_error={exc}", file=sys.stderr)
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
    print(f"attack_attempts={','.join(attack_attempts)}")
    print("attack_sent=yes")
    print(f"victim_damage_packets={victim_result['damage_packets']}")
    print(f"victim_damage_total={victim_result['damage_total']}")
    print(f"victim_last_damage={victim_result['last_damage']}")
    print(f"victim_attack_failures={victim_result['attack_failures']}")
    print(f"attacker_damage_packets={attacker_result['damage_packets']}")
    print(f"attacker_attack_failures={attacker_result['attack_failures']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
