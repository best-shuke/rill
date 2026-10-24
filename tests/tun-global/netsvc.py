"""Services and a client for the rill TUN e2e test.

  netsvc.py serve                 echo on :7000 (v4+v6), DNS on 10.10.9.9:53
  netsvc.py echo HOST PORT [HOLD] connect, echo one line, optionally hold
"""
import socket
import struct
import sys
import threading
import time


def echo_server(family, addr):
    s = socket.socket(family, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.bind((addr, 7000))
    s.listen(64)
    while True:
        conn, _ = s.accept()

        def handle(c):
            with c:
                while True:
                    data = c.recv(4096)
                    if not data:
                        return
                    c.sendall(data)

        threading.Thread(target=handle, args=(conn,), daemon=True).start()


def dns_answer(query):
    qid = query[:2]
    # Walk the question name.
    i, labels = 12, []
    while query[i]:
        n = query[i]
        labels.append(query[i + 1:i + 1 + n].decode())
        i += n + 1
    qtype = struct.unpack("!H", query[i + 1:i + 3])[0]
    question = query[12:i + 5]
    name = ".".join(labels)
    ip = "10.10.8.8" if name.startswith("excluded") else "10.10.9.9"
    header = qid + b"\x81\x80" + struct.pack("!HHHH", 1, 1 if qtype == 1 else 0, 0, 0)
    answer = b""
    if qtype == 1:
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + socket.inet_aton(ip)
    return header + question + answer


def dns_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("10.10.9.9", 53))
    while True:
        data, peer = s.recvfrom(512)
        try:
            s.sendto(dns_answer(data), peer)
        except Exception:
            pass


def serve():
    for family, addr in [(socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")]:
        threading.Thread(target=echo_server, args=(family, addr), daemon=True).start()
    threading.Thread(target=dns_server, daemon=True).start()
    print("ready", flush=True)
    while True:
        time.sleep(3600)


def echo(host, port, hold=0.0):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((host, int(port)))
        s.sendall(b"ping\n")
        got = s.recv(16)
        if hold:
            time.sleep(hold)
        print("ok" if got == b"ping\n" else f"bad {got!r}")
    except OSError as e:
        print(f"error {e.errno} {e.strerror}")
    finally:
        s.close()


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        serve()
    else:
        echo(sys.argv[2], sys.argv[3], float(sys.argv[4]) if len(sys.argv) > 4 else 0.0)
