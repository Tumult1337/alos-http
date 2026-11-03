import base64
import os
import socket
import ssl
import struct
import sys


def read_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("closed")
        buf += chunk
    return buf


def send_frame(sock, opcode, payload):
    head = bytes([0x80 | opcode])
    n = len(payload)
    if n < 126:
        head += bytes([0x80 | n])
    elif n < 65536:
        head += bytes([0x80 | 126]) + struct.pack("!H", n)
    else:
        head += bytes([0x80 | 127]) + struct.pack("!Q", n)
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    sock.sendall(head + mask + masked)


def recv_frame(sock):
    b0, b1 = read_exact(sock, 2)
    opcode = b0 & 0x0F
    n = b1 & 0x7F
    if n == 126:
        n = struct.unpack("!H", read_exact(sock, 2))[0]
    elif n == 127:
        n = struct.unpack("!Q", read_exact(sock, 8))[0]
    if b1 & 0x80:
        mask = read_exact(sock, 4)
        data = read_exact(sock, n)
        data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    else:
        data = read_exact(sock, n)
    return b0 & 0x80, opcode, data


def main():
    scheme, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
    raw = socket.create_connection((host, port), timeout=5)
    if scheme == "wss":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["http/1.1"])
        sock = ctx.wrap_socket(raw, server_hostname="localhost")
    else:
        sock = raw
    key = base64.b64encode(os.urandom(16)).decode()
    req = (
        "GET /ws HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    )
    sock.sendall(req.encode())
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = sock.recv(1)
        if not chunk:
            raise EOFError("closed during handshake")
        head += chunk
    status = head.split(b"\r\n", 1)[0]
    if b" 101 " not in status + b" ":
        print("FAIL handshake", status)
        sys.exit(1)
    if b"permessage-deflate" in head.lower():
        print("FAIL permessage-deflate negotiated")
        sys.exit(1)
    ok = True
    for opcode, size in ((1, 64), (1, 16384), (2, 64), (2, 16384)):
        payload = (b"abcdefghijklmnopqrstuvwxyz0123456789" * (size // 36 + 1))[:size]
        if opcode == 2:
            payload = bytes((i * 7) & 0xFF for i in range(size))
        send_frame(sock, opcode, payload)
        while True:
            fin, rop, data = recv_frame(sock)
            if rop in (9, 10):
                continue
            break
        good = fin and rop == opcode and data == payload
        ok = ok and good
        print(f"{scheme} opcode={opcode} size={size} echo={'ok' if good else 'BAD'} got_op={rop} got_len={len(data)}")
    send_frame(sock, 8, struct.pack("!H", 1000))
    sock.close()
    sys.exit(0 if ok else 1)


main()
