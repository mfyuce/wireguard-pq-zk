#!/usr/bin/env python3
"""wgzk_probe: sends what an attacker could send.

Test tool for the acceptance tests of docs/protocol-r1.md. It needs nothing
beyond the Python standard library and runs inside the test machines.

  capture   record initiations (type 0xA1) that leave this host
  send      send a recorded initiation again, unchanged or modified
  tls       send side-channel messages with random content, or offer TLS 1.2
  verdict   send SET_VERIFY as the calling user
  proof     answer the next NEED_PROOF of an interface with a given proof
  events    print the events of the wgzk family

Every subcommand prints one JSON object per line.
"""

import argparse
import base64
import hashlib
import json
import os
import select
import socket
import ssl
import struct
import sys
import time

INIT_LEN = 244
INIT_TYPE = b"\xa1\x00\x00\x00"
RESPONSE_LEN = 92
OFF_SENDER = 4
OFF_STATIC = 40
OFF_R = 116
OFF_S = 148
OFF_NONCE = 180
OFF_MAC1 = 212
OFF_MAC2 = 228
SIDE_MSG_LEN = 4 + 32 + 1088

# Generic netlink
NETLINK_GENERIC = 16
GENL_ID_CTRL = 0x10
CTRL_CMD_GETFAMILY = 3
CTRL_ATTR_FAMILY_ID = 1
CTRL_ATTR_FAMILY_NAME = 2
CTRL_ATTR_MCAST_GROUPS = 7
CTRL_ATTR_MCAST_GRP_NAME = 1
CTRL_ATTR_MCAST_GRP_ID = 2
NLM_F_REQUEST = 1
NLM_F_ACK = 4
NLMSG_ERROR = 2
SOL_NETLINK = 270
NETLINK_ADD_MEMBERSHIP = 1

WGZK_FAMILY = "wgzk"
WGZK_VERSION = 2
CMD_SET_PROOF = 2
CMD_NEED_PROOF = 3
CMD_SET_VERIFY = 4
CMD_NEED_VERIFY = 5
CMD_NAMES = {CMD_NEED_PROOF: "NEED_PROOF", CMD_NEED_VERIFY: "NEED_VERIFY"}
ATTR_PEER_INDEX = 1
ATTR_RESULT = 2
ATTR_PEER_ID = 3
ATTR_R = 4
ATTR_S = 5
ATTR_IFINDEX = 6
ATTR_PEER_PUB = 7
ATTR_TOKEN = 8
ATTR_SESSION_NONCE = 9
ATTR_PENDING_ID = 10
ATTR_LOCAL_PUB = 11


def out(**kw):
    print(json.dumps(kw, sort_keys=True), flush=True)


def mac1(gw_pub, msg, upto=OFF_MAC1):
    key = hashlib.blake2s(b"mac1----" + gw_pub).digest()
    return hashlib.blake2s(msg[:upto], digest_size=16, key=key).digest()


def as_plain_initiation(gw_pub, rec):
    """The WireGuard initiation (type 1, 148 bytes) that the same sender would
    have sent without a proof: same keys, same timestamp, MAC computed again."""
    msg = b"\x01\x00\x00\x00" + bytes(rec[4:OFF_R])
    return msg + mac1(gw_pub, msg, len(msg)) + bytes(16)


def load_records(path):
    data = open(path, "rb").read()
    if not data or len(data) % INIT_LEN:
        sys.exit(f"{path}: {len(data)} bytes, expected a multiple of {INIT_LEN}")
    return [data[i:i + INIT_LEN] for i in range(0, len(data), INIT_LEN)]


def hostport(text):
    host, _, port = text.rpartition(":")
    return host, int(port)


# ── capture ───────────────────────────────────────────────────────────────────

def cmd_capture(a):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0003))
    s.bind((a.iface, 0))
    deadline = time.monotonic() + a.timeout
    got = 0
    with open(a.out, "wb") as f:
        while got < a.count:
            left = deadline - time.monotonic()
            if left <= 0:
                break
            if not select.select([s], [], [], left)[0]:
                break
            pkt, addr = s.recvfrom(65535)
            if addr[1] != 0x0800 or addr[2] != 4:  # IPv4, PACKET_OUTGOING
                continue
            if len(pkt) < 28 or pkt[0] >> 4 != 4 or pkt[9] != 17:
                continue
            ihl = (pkt[0] & 15) * 4
            sport, dport, ulen = struct.unpack_from("!HHH", pkt, ihl)
            payload = pkt[ihl + 8:ihl + ulen]
            if dport != a.dport or len(payload) != INIT_LEN or payload[:4] != INIT_TYPE:
                continue
            f.write(payload)
            got += 1
            extra = {}
            if a.gw_pub:  # checks this tool's MAC computation against the kernel's
                extra["mac1_ok"] = mac1(base64.b64decode(a.gw_pub), payload) == payload[OFF_MAC1:OFF_MAC2]
            out(event="captured", n=got, sport=sport,
                sender_index=struct.unpack_from("<I", payload, OFF_SENDER)[0],
                nonce4=payload[OFF_NONCE:OFF_NONCE + 4].hex(), **extra)
    out(event="capture_done", captured=got, wanted=a.count)
    return 0 if got == a.count else 1


# ── send ──────────────────────────────────────────────────────────────────────

MUTATIONS = {"s": OFF_S, "r": OFF_R, "nonce": OFF_NONCE, "static": OFF_STATIC}


def cmd_send(a):
    rec = bytearray(load_records(a.infile)[a.index])
    if (a.mutate != "none" or a.plain) and not a.gw_pub:
        sys.exit("--mutate and --plain need --gw-pub: the MAC has to be computed again")
    if a.mutate != "none":
        rec[MUTATIONS[a.mutate] + 5] ^= 0x01
        rec[OFF_MAC1:OFF_MAC2] = mac1(base64.b64decode(a.gw_pub), bytes(rec))
        rec[OFF_MAC2:] = bytes(16)
    sender_index = struct.unpack_from("<I", rec, OFF_SENDER)[0]
    nonce4 = bytes(rec[OFF_NONCE:OFF_NONCE + 4]).hex()
    if a.plain:
        rec = bytearray(as_plain_initiation(base64.b64decode(a.gw_pub), rec))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if a.sport:
        s.bind(("", a.sport))
    dst = hostport(a.dst)
    gap = 1.0 / a.rate if a.rate > 0 else 0.0
    start = time.monotonic()
    for i in range(a.count):
        s.sendto(bytes(rec), dst)
        if gap:
            wait = start + (i + 1) * gap - time.monotonic()
            if wait > 0:
                time.sleep(wait)
    sent_in = time.monotonic() - start
    responses = cookies = other = 0
    deadline = time.monotonic() + a.listen
    while True:
        left = deadline - time.monotonic()
        if left <= 0 or not select.select([s], [], [], left)[0]:
            break
        data, _ = s.recvfrom(65535)
        if len(data) == RESPONSE_LEN and data[:4] == b"\x02\x00\x00\x00":
            responses += 1
        elif len(data) == 64 and data[:4] == b"\x03\x00\x00\x00":
            cookies += 1
        else:
            other += 1
    out(event="sent", count=a.count, mutate=a.mutate, plain=a.plain, bytes=len(rec),
        seconds=round(sent_in, 3), sender_index=sender_index, nonce4=nonce4,
        responses=responses, cookie_replies=cookies, other_replies=other)
    return 0


# ── tls ───────────────────────────────────────────────────────────────────────

def cmd_tls(a):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if a.tls12:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    else:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    dst = hostport(a.dst)
    delivered = refused = 0
    errors = {}
    held = []
    start = time.monotonic()
    for i in range(a.count):
        try:
            raw = socket.create_connection(dst, timeout=a.timeout)
            if a.hold:
                held.append(raw)  # TCP only: never starts the TLS handshake
                delivered += 1
                continue
            with ctx.wrap_socket(raw, server_hostname="wgzk-gateway") as t:
                t.sendall(os.urandom(SIDE_MSG_LEN)[:a.length])
                delivered += 1
        except OSError as e:  # includes ssl.SSLError and timeouts
            refused += 1
            name = type(e).__name__
            errors[name] = errors.get(name, 0) + 1
    if a.hold:
        time.sleep(a.hold)
        still_open = 0
        for h in held:
            h.setblocking(False)
            try:
                if h.recv(1) == b"":
                    continue  # closed by the gateway
            except BlockingIOError:
                still_open += 1
            except OSError:
                continue
        out(event="tls_hold", opened=delivered, refused=refused,
            open_after_hold=still_open, hold_seconds=a.hold)
        return 0
    out(event="tls_done", count=a.count, delivered=delivered, refused=refused,
        errors=errors, tls12=a.tls12, length=a.length,
        seconds=round(time.monotonic() - start, 3))
    return 0


# ── generic netlink ───────────────────────────────────────────────────────────

def nla(kind, payload):
    length = 4 + len(payload)
    return struct.pack("HH", length, kind) + payload + bytes((4 - length % 4) % 4)


def parse_attrs(buf):
    attrs = {}
    i = 0
    while i + 4 <= len(buf):
        length, kind = struct.unpack_from("HH", buf, i)
        if length < 4:
            break
        attrs[kind & 0x3FFF] = buf[i + 4:i + length]
        i += (length + 3) & ~3
    return attrs


class Genl:
    def __init__(self):
        self.s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
        self.s.bind((0, 0))
        self.seq = 0
        self.family, self.groups = self._resolve()

    def _messages(self, timeout):
        if not select.select([self.s], [], [], timeout)[0]:
            return
        buf = self.s.recv(65535)
        i = 0
        while i + 16 <= len(buf):
            length, kind, _flags, seq, _pid = struct.unpack_from("IHHII", buf, i)
            if length < 16:
                break
            yield kind, seq, buf[i + 16:i + length]
            i += (length + 3) & ~3

    def request(self, family, cmd, version, attrs):
        """Returns (errno, replies); errno 0 means acknowledged."""
        self.seq += 1
        body = struct.pack("BBH", cmd, version, 0) + attrs
        self.s.send(struct.pack("IHHII", 16 + len(body), family,
                                NLM_F_REQUEST | NLM_F_ACK, self.seq, 0) + body)
        replies = []
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            for kind, seq, payload in self._messages(deadline - time.monotonic()):
                if seq != self.seq:
                    continue
                if kind == NLMSG_ERROR:
                    return -struct.unpack_from("i", payload)[0], replies
                replies.append(payload)
        sys.exit("netlink: no acknowledgement")

    def _resolve(self):
        self.family = None
        err, replies = self.request(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 1,
                                    nla(CTRL_ATTR_FAMILY_NAME, WGZK_FAMILY.encode() + b"\0"))
        if err or not replies:
            sys.exit(f"netlink: family {WGZK_FAMILY} not found (errno {err}); is the module loaded?")
        attrs = parse_attrs(replies[0][4:])
        family = struct.unpack("H", attrs[CTRL_ATTR_FAMILY_ID])[0]
        groups = {}
        for grp in parse_attrs(attrs.get(CTRL_ATTR_MCAST_GROUPS, b"")).values():
            g = parse_attrs(grp)
            name = g[CTRL_ATTR_MCAST_GRP_NAME].rstrip(b"\0").decode()
            groups[name] = struct.unpack("I", g[CTRL_ATTR_MCAST_GRP_ID])[0]
        return family, groups

    def listen(self):
        self.s.setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, self.groups["events"])

    def events(self, timeout):
        """Yields (cmd, attrs) until `timeout` seconds have passed."""
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                return
            for kind, _seq, payload in self._messages(left):
                if kind == self.family and len(payload) >= 4:
                    yield payload[0], parse_attrs(payload[4:])


def describe(cmd, attrs):
    d = {"event": CMD_NAMES.get(cmd, f"cmd{cmd}")}
    for name, kind, fmt in (("ifindex", ATTR_IFINDEX, "I"), ("peer_id", ATTR_PEER_ID, "Q"),
                            ("pending_id", ATTR_PENDING_ID, "Q"), ("token", ATTR_TOKEN, "I"),
                            ("sender_index", ATTR_PEER_INDEX, "I")):
        if kind in attrs:
            d[name] = struct.unpack(fmt, attrs[kind])[0]
    for name, kind in (("peer_pub", ATTR_PEER_PUB), ("local_pub", ATTR_LOCAL_PUB)):
        if kind in attrs:
            d[name] = base64.b64encode(attrs[kind]).decode()
    if ATTR_SESSION_NONCE in attrs:
        d["nonce4"] = attrs[ATTR_SESSION_NONCE][:4].hex()
    return d


def cmd_verdict(a):
    g = Genl()
    err, _ = g.request(g.family, CMD_SET_VERIFY, WGZK_VERSION,
                       nla(ATTR_PENDING_ID, struct.pack("Q", a.pending_id)) +
                       nla(ATTR_RESULT, struct.pack("B", a.result)))
    out(event="verdict", uid=os.getuid(), pending_id=a.pending_id, result=a.result,
        errno=err, error=os.strerror(err) if err else "")
    return 0


def cmd_events(a):
    g = Genl()
    g.listen()
    out(event="listening", family=g.family, seconds=a.seconds)
    n = 0
    for cmd, attrs in g.events(a.seconds):
        out(**describe(cmd, attrs))
        n += 1
    out(event="events_done", seen=n)
    return 0


def cmd_proof(a):
    """Answers the next NEED_PROOF of an interface with the proof of a recorded
    initiation. The kernel then sends an initiation that carries this interface's
    key and the other connection's proof."""
    rec = load_records(a.infile)[a.index]
    ifindex = socket.if_nametoindex(a.iface)
    g = Genl()
    g.listen()
    out(event="waiting", iface=a.iface, ifindex=ifindex, seconds=a.seconds)
    for cmd, attrs in g.events(a.seconds):
        if cmd != CMD_NEED_PROOF or ATTR_IFINDEX not in attrs or ATTR_PEER_ID not in attrs:
            continue
        if struct.unpack("I", attrs[ATTR_IFINDEX])[0] != ifindex:
            continue
        err, _ = g.request(g.family, CMD_SET_PROOF, WGZK_VERSION,
                           nla(ATTR_PEER_ID, attrs[ATTR_PEER_ID]) +
                           nla(ATTR_IFINDEX, struct.pack("I", ifindex)) +
                           nla(ATTR_R, rec[OFF_R:OFF_S]) +
                           nla(ATTR_S, rec[OFF_S:OFF_NONCE]) +
                           nla(ATTR_SESSION_NONCE, rec[OFF_NONCE:OFF_MAC1]))
        out(event="proof_set", errno=err, nonce4=rec[OFF_NONCE:OFF_NONCE + 4].hex(),
            **{k: v for k, v in describe(cmd, attrs).items() if k != "event"})
        return 0 if err == 0 else 1
    out(event="proof_timeout")
    return 1


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("capture")
    c.add_argument("--iface", required=True)
    c.add_argument("--dport", type=int, default=51921)
    c.add_argument("--out", required=True)
    c.add_argument("--count", type=int, default=1)
    c.add_argument("--timeout", type=float, default=10)
    c.add_argument("--gw-pub", help="WireGuard public key of the gateway, base64")
    c.set_defaults(fn=cmd_capture)

    c = sub.add_parser("send")
    c.add_argument("--in", dest="infile", required=True)
    c.add_argument("--index", type=int, default=0)
    c.add_argument("--dst", required=True, help="address:port of the gateway")
    c.add_argument("--mutate", choices=["none"] + sorted(MUTATIONS), default="none")
    c.add_argument("--gw-pub", help="WireGuard public key of the gateway, base64")
    c.add_argument("--plain", action="store_true",
                   help="send it as a WireGuard initiation without proof (type 1)")
    c.add_argument("--count", type=int, default=1)
    c.add_argument("--rate", type=float, default=0, help="packets per second, 0: no pause")
    c.add_argument("--sport", type=int, default=0)
    c.add_argument("--listen", type=float, default=1.0, help="seconds to wait for answers")
    c.set_defaults(fn=cmd_send)

    c = sub.add_parser("tls")
    c.add_argument("--dst", required=True, help="address:port of the side channel")
    c.add_argument("--count", type=int, default=1)
    c.add_argument("--length", type=int, default=SIDE_MSG_LEN)
    c.add_argument("--timeout", type=float, default=3)
    c.add_argument("--tls12", action="store_true", help="offer TLS 1.2 only")
    c.add_argument("--hold", type=float, default=0,
                   help="open TCP connections, send nothing, report how many are open after this many seconds")
    c.set_defaults(fn=cmd_tls)

    c = sub.add_parser("verdict")
    c.add_argument("--pending-id", type=int, required=True)
    c.add_argument("--result", type=int, default=1)
    c.set_defaults(fn=cmd_verdict)

    c = sub.add_parser("events")
    c.add_argument("--seconds", type=float, default=10)
    c.set_defaults(fn=cmd_events)

    c = sub.add_parser("proof")
    c.add_argument("--iface", required=True)
    c.add_argument("--in", dest="infile", required=True)
    c.add_argument("--index", type=int, default=0)
    c.add_argument("--seconds", type=float, default=10)
    c.set_defaults(fn=cmd_proof)

    a = p.parse_args()
    sys.exit(a.fn(a))


if __name__ == "__main__":
    main()
