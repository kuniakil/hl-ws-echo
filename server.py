#!/usr/bin/env python3
"""Minimal RFC6455 WebSocket echo server (stdlib only).

Purpose: measure whether the platform's ingress supports the WebSocket
upgrade for user-deployed apps, and how long an idle connection survives.
Not a proxy: it echoes bytes back to the same client.
"""
import base64, hashlib, os, socket, struct, threading, sys, time

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
PORT = int(os.environ.get("PORT", "8080"))


def handshake(conn):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            return None
        data += chunk
    head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    key = None
    for line in head.split("\r\n")[1:]:
        name, _, value = line.partition(":")
        if name.strip().lower() == "sec-websocket-key":
            key = value.strip()
    if key is None:
        conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
        return None
    accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
    conn.sendall(
        ("HTTP/1.1 101 Switching Protocols\r\n"
         "Upgrade: websocket\r\nConnection: Upgrade\r\n"
         f"Sec-WebSocket-Accept: {accept}\r\n\r\n").encode()
    )
    return True


def recv_frame(conn):
    def rd(n):
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("closed")
            buf += chunk
        return buf
    b1, b2 = rd(2)
    opcode = b1 & 0x0F
    masked = b2 & 0x80
    length = b2 & 0x7F
    if length == 126:
        length = struct.unpack(">H", rd(2))[0]
    elif length == 127:
        length = struct.unpack(">Q", rd(8))[0]
    mask = rd(4) if masked else None
    payload = rd(length) if length else b""
    if mask:
        payload = bytes(c ^ mask[i % 4] for i, c in enumerate(payload))
    return opcode, payload


def send_frame(conn, payload, opcode=1):
    header = bytes([0x80 | opcode])
    n = len(payload)
    if n < 126:
        header += bytes([n])
    elif n < 65536:
        header += bytes([126]) + struct.pack(">H", n)
    else:
        header += bytes([127]) + struct.pack(">Q", n)
    conn.sendall(header + payload)


def handle(conn, addr):
    try:
        conn.settimeout(300)
        if not handshake(conn):
            return
        print(f"[ws] upgraded {addr}", flush=True)
        while True:
            opcode, payload = recv_frame(conn)
            if opcode == 0x8:
                print(f"[ws] close {addr}", flush=True)
                break
            if opcode == 0x9:
                send_frame(conn, payload, 0xA)
                continue
            if opcode in (0x1, 0x2):
                send_frame(conn, payload, opcode)
    except Exception as e:
        print(f"[ws] {addr} {type(e).__name__}: {e}", flush=True)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT))
    srv.listen(64)
    print(f"[ws] listening on 0.0.0.0:{PORT}", flush=True)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
