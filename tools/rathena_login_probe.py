#!/usr/bin/env python3

import argparse
import socket
import struct
import sys


def build_login_packet(username: str, password: str, version: int, clienttype: int) -> bytes:
    username_bytes = username.encode("ascii", "ignore")[:24]
    password_bytes = password.encode("ascii", "ignore")[:24]
    return struct.pack(
        "<HI24s24sB",
        0x64,
        version,
        username_bytes.ljust(24, b"\0"),
        password_bytes.ljust(24, b"\0"),
        clienttype,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe rAthena login-server with a raw CA_LOGIN packet.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=6900)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--version", type=int, default=0)
    parser.add_argument("--clienttype", type=int, default=0)
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()

    packet = build_login_packet(args.username, args.password, args.version, args.clienttype)

    sock = socket.socket()
    sock.settimeout(args.timeout)
    try:
        sock.connect((args.host, args.port))
        sock.sendall(packet)
        response = sock.recv(512)
    except Exception as exc:
        print(f"probe_error={exc}", file=sys.stderr)
        return 2
    finally:
        sock.close()

    print(f"recv_len={len(response)}")
    print(f"recv_hex={response.hex()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
