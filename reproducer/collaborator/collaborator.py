#!/usr/bin/env python3
"""
Controlled collaborator for the log4shell-chain reproducers.

This is the observability sink the sandbox runs alongside the reproducer. Its ONLY
job is to RECORD inbound connections carrying a per-trial token (Case A) or an
attempted JDBC/JNDI DataSource resolution (Case C). It is deliberately a PASSIVE
RECORDER:

  * It does NOT serve a malicious Java class.
  * It does NOT return an LDAP referral that could trigger code loading.
  * It does NOT return any code-exec payload of any kind.

This keeps the proof EFFECT-ONLY (RFC 0003 / RFC 0001 inv. 8): the outbound
network callback is sufficient evidence that the JNDI/JDBC lookup fired. We do not
weaponize the RCE.

Protocol choice: we listen as a plain TCP socket. Both an LDAP client (Case A
${jndi:ldap://...}) and a JDBC DataSource JNDI resolution (Case C) will OPEN a TCP
connection to us before any protocol handshake completes; the connection event
itself -- with the bytes of the first packet, which contain the token / DN -- is
the recorded observable. We log every connection to stdout and to a JSONL file so
the sandbox can correlate by token. We then close the socket; because we never
reply with a referral or a class, no code path toward RCE is opened. See README.md
for the LDAP-vs-TCP choice and its caveat (NOTES.md tracks it as an open item).
"""
import json
import os
import socket
import sys
import threading
import time

HOST = os.environ.get("COLLABORATOR_BIND", "0.0.0.0")
PORT = int(os.environ.get("COLLABORATOR_PORT", "1389"))
RECORD_PATH = os.environ.get("COLLABORATOR_RECORD", "/records/callbacks.jsonl")


def record(entry: dict) -> None:
    line = json.dumps(entry, sort_keys=True)
    print("[collaborator] " + line, flush=True)
    try:
        os.makedirs(os.path.dirname(RECORD_PATH), exist_ok=True)
        with open(RECORD_PATH, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError as exc:
        print(f"[collaborator] WARN could not persist record: {exc}", flush=True)


def handle(conn: socket.socket, addr) -> None:
    conn.settimeout(2.0)
    first = b""
    try:
        first = conn.recv(4096)
    except (socket.timeout, OSError):
        pass
    finally:
        # We never reply with a referral / class. Just close -> no RCE path.
        try:
            conn.close()
        except OSError:
            pass
    record(
        {
            "event": "inbound_callback",
            "ts": time.time(),
            "peer": f"{addr[0]}:{addr[1]}",
            # First packet bytes carry the JNDI DN / token; record a safe
            # printable preview so the sandbox can correlate to the per-trial token.
            "first_bytes_preview": first[:256].decode("latin-1", "replace"),
            "first_bytes_len": len(first),
        }
    )


def main() -> int:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(64)
    print(f"[collaborator] passive recorder listening on {HOST}:{PORT} "
          f"(records -> {RECORD_PATH}); serves NO payload", flush=True)
    record({"event": "started", "ts": time.time(), "bind": f"{HOST}:{PORT}"})
    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("[collaborator] shutting down", flush=True)
    finally:
        srv.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
