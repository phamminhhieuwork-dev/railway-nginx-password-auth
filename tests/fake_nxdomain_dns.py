#!/usr/bin/env python3
"""Local-only DNS stub for tests/oauth_log_redaction.py: answers NXDOMAIN to every query on 127.0.0.1:PORT."""
import socket, struct, sys

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", int(sys.argv[1])))
while True:
    data, addr = sock.recvfrom(512)
    i = 12
    while data[i]:
        i += data[i] + 1
    question = data[12:i + 5]
    sock.sendto(data[:2] + struct.pack("!HHHHH", 0x8183, 1, 0, 0, 0) + question, addr)
