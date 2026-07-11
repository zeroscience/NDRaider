"""Tiny TCP capture proxy: listen on :49153, forward to the RPC server :49152,
and dump every client->server DCE/RPC PDU as hex (split by frag_length).

Run one client through it at a time (known-good NdrTestClient, then ndr-fuzz),
each label written to a file so we can diff the bind/auth3/request PDUs.
"""
import socket, struct, sys, threading

LISTEN = ("127.0.0.1", 49153)
UPSTREAM = ("127.0.0.1", 49152)
PTYPE = {0: "REQUEST", 2: "RESPONSE", 3: "FAULT", 11: "BIND", 12: "BIND_ACK", 13: "BIND_NAK", 16: "AUTH3"}


def dump_pdus(buf, label, out):
    off = 0
    while off + 16 <= len(buf):
        if buf[off] != 5:
            break
        frag = struct.unpack_from("<H", buf, off + 8)[0]
        if frag < 16 or off + frag > len(buf):
            break
        pdu = buf[off:off + frag]
        pt = PTYPE.get(pdu[2], f"ptype{pdu[2]}")
        auth_len = struct.unpack_from("<H", pdu, 10)[0]
        line = f"[{label}] {pt} len={frag} auth_len={auth_len}: {pdu.hex()}"
        print(line)
        out.write(line + "\n")
        off += frag


def pump(src, dst, label, out, capture):
    acc = b""
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            if capture:
                acc += data
                # dump any complete PDUs accumulated
                while len(acc) >= 16 and acc[0] == 5:
                    frag = struct.unpack_from("<H", acc, 8)[0]
                    if frag < 16 or len(acc) < frag:
                        break
                    dump_pdus(acc[:frag], label, out)
                    acc = acc[frag:]
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle(client, label, out):
    up = socket.create_connection(UPSTREAM)
    t1 = threading.Thread(target=pump, args=(client, up, label, out, True))
    t2 = threading.Thread(target=pump, args=(up, client, label + "<-", out, False))
    t1.start(); t2.start(); t1.join(); t2.join()
    client.close(); up.close()


def main():
    label = sys.argv[1] if len(sys.argv) > 1 else "cap"
    outpath = sys.argv[2] if len(sys.argv) > 2 else "capture.txt"
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(LISTEN)
    srv.listen(4)
    print(f"proxy {LISTEN} -> {UPSTREAM}, label={label}, out={outpath}")
    with open(outpath, "w") as out:
        while True:
            c, _ = srv.accept()
            handle(c, label, out)
            out.flush()


if __name__ == "__main__":
    main()
