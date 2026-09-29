#!/usr/bin/env python3
"""Acceptance tests of protocol R1 (docs/protocol-r1.md) on the test bed.

Runs on the host, in the repository root, with both machines up:

    python3 bench/acceptance/run.py            # all tests
    python3 bench/acceptance/run.py --list
    python3 bench/acceptance/run.py auth-replay k-locks

Every test starts from freshly provisioned machines (module reloaded), states
what it expects, and records what it saw. Results go to
bench/results/acceptance/<UTC time>/: results.jsonl, summary.md and one log
per test. The exit status is 0 only if no test failed.

A test that needs the daemon built with the feature "fault-injection" is
reported as skipped when that build is not installed in the client machine.
"""

import argparse
import datetime
import json
import os
import re
import shlex
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "bench"))
import rig as rigmod  # noqa: E402

# Address of the gateway on the test network and the interface of the machines
# there: both come from the test bed (see Rig) and are set before the first test.
GW_IP = None
NIC = None
GW_PORT = 51921
TLS_PORT = 51821
GW_ADDR = "fd57:475a:4b00::1"
TUNNEL_NET = "fd57:475a:4b00::/64"
IF_GW = "wg1r"
IF_CL = "wg1l"
PROBE = "python3 /usr/local/bin/wgzk_probe.py"
# Test tools and logging of a machine: the probe where every user can read it,
# and a journal that drops no line of a flood.
TOOLS = ("install -m 755 /vagrant/bench/acceptance/wgzk_probe.py /usr/local/bin/wgzk_probe.py; "
         "mkdir -p /etc/systemd/journald.conf.d; "
         "printf '[Journal]\\nRateLimitIntervalSec=0\\n' > /etc/systemd/journald.conf.d/wgzk.conf; "
         "systemctl restart systemd-journald; ")
FAULT_BIN = "/usr/local/bin/wg-zk-daemon-fault"
STATS = "/sys/kernel/debug/wgzk/stats"
BLOCK = f"iptables -I INPUT -p udp --dport {GW_PORT} -j DROP"
UNBLOCK = f"iptables -D INPUT -p udp --dport {GW_PORT} -j DROP"
PING1 = f"ping -6 -c 1 -W 2 {GW_ADDR}"


class Skip(Exception):
    pass


class Rig:
    def __init__(self, outdir):
        global GW_IP, NIC
        self.outdir = outdir
        self.bed = rigmod.Bed("wgzk", workdir=outdir)
        GW_IP, NIC = self.bed.gw_ip, self.bed.nic
        self.bed.push_share()
        self.gw_pub = open(os.path.join(ROOT, "vagrant/keys/public_right")).read().strip()
        self.log = None
        self.variant = None

    # ── remote execution ─────────────────────────────────────────────────────
    def run(self, vm, script, timeout=180):
        """Runs `script` as root in `vm`; returns (exit status, output)."""
        rc, out, err = self.bed.run(vm, script, timeout)
        out += err
        if self.log:
            self.log.write(f"\n$ [{vm}] {script}\n{out}[exit {rc}]\n")
            self.log.flush()
        return rc, out

    def gw(self, script, **kw):
        return self.run("gateway", script, **kw)

    def cl(self, script, **kw):
        return self.run("client", script, **kw)

    def must(self, vm, script, **kw):
        rc, out = self.run(vm, script, **kw)
        if rc != 0:
            raise RuntimeError(f"setup step failed in {vm} (exit {rc}): {script}\n{out}")
        return out

    # ── state ────────────────────────────────────────────────────────────────
    def provision(self, variant):
        self.must("gateway", TOOLS + "rm -rf /etc/systemd/system/wgzk.service.d /etc/wgzk-test.env; "
                  "pkill tcpdump; bash /vagrant/vagrant/02-load-module.sh && "
                  f"WGZK_VARIANT={variant} bash /vagrant/vagrant/03-gateway.sh")
        self.must("gateway", f"{UNBLOCK} 2>/dev/null; true")
        self.must("client", TOOLS + "rm -rf /etc/systemd/system/wgzk.service.d /etc/wgzk-test.env; "
                  "bash /vagrant/vagrant/02-load-module.sh && "
                  f"PEER_IP={GW_IP} WGZK_VARIANT={variant} bash /vagrant/vagrant/03-client.sh")
        self.variant = variant

    def stats(self, vm):
        out = self.must(vm, f"cat {STATS}")
        return {k: int(v) for k, v in (line.split() for line in out.splitlines() if line.strip())}

    def peers(self):
        """Peers of the gateway: {public key: allowed ips}."""
        out = self.must("gateway", f"wg show {IF_GW} allowed-ips")
        return {p[0]: " ".join(p[1:]) for p in (line.split() for line in out.splitlines()) if p}

    def cursor(self, vm):
        out = self.must(vm, "journalctl -u wgzk -n 1 --show-cursor -o cat --no-pager | tail -1")
        m = re.search(r"cursor: (\S+)", out)
        return m.group(1) if m else ""

    def journal(self, vm, cursor):
        after = f"--after-cursor={shlex.quote(cursor)}" if cursor else ""
        return self.must(vm, f"journalctl -u wgzk -o cat --no-pager {after}")

    def timing(self, vm, cursor):
        """The [timing] lines since `cursor`, as dictionaries."""
        lines = []
        for line in self.journal(vm, cursor).splitlines():
            if line.startswith("[timing] "):
                lines.append(dict(kv.split("=", 1) for kv in line.split()[1:] if "=" in kv))
        return lines

    def probe(self, vm, args, prefix="", timeout=180):
        rc, out = self.run(vm, f"{prefix}{PROBE} {args}", timeout=timeout)
        events = []
        for line in out.splitlines():
            if line.startswith("{"):
                try:
                    events.append(json.loads(line))
                except ValueError:
                    pass
        return rc, events

    def session_key(self):
        return self.must("client", f"wg show {IF_CL} public-key").strip()

    def new_connection(self):
        self.must("client", f"wg-zk-daemon new-connection --iface {IF_CL} >/dev/null")
        return self.session_key()

    def ping(self, count=1, wait=2):
        rc, _ = self.cl(f"ping -6 -c {count} -W {wait} {GW_ADDR}")
        return rc == 0

    def client_handshake_age(self):
        """Seconds since the last completed handshake of the client, or None."""
        out = self.must("client", f"wg show {IF_CL} latest-handshakes").split()
        if len(out) < 2 or out[1] == "0":
            return None
        now = int(self.must("client", "date +%s"))
        return now - int(out[1])

    def sample(self, vm, command, interval, path):
        """Runs `command` every `interval` seconds in `vm` and collects its output in `path`."""
        self.must(vm, f"(while sleep {interval}; do {command}; done > {path} 2>&1 </dev/null & "
                  "echo $! > /tmp/sampler.pid); true")

    def stop_sampling(self, vm):
        self.must(vm, "kill $(cat /tmp/sampler.pid) 2>/dev/null; rm -f /tmp/sampler.pid; true")

    def have_fault_build(self):
        rc, _ = self.cl(f"test -x {FAULT_BIN}")
        return rc == 0

    def daemon(self, vm, env=None, binary=None):
        """Restarts the daemon of `vm` with settings that override the provisioned ones."""
        envfile = "\n".join(f"{k}={v}" for k, v in (env or {}).items())
        dropin = "[Service]\nEnvironmentFile=/etc/wgzk-test.env\n"
        if binary:
            dropin += f"ExecStart=\nExecStart={binary}\n"
        self.must(vm, "mkdir -p /etc/systemd/system/wgzk.service.d; umask 077; "
                  f"printf '%s\\n' {shlex.quote(envfile)} > /etc/wgzk-test.env; "
                  f"printf '%s' {shlex.quote(dropin)} > /etc/systemd/system/wgzk.service.d/test.conf; "
                  "systemctl daemon-reload; systemctl restart wgzk; sleep 1; systemctl is-active wgzk")

    def client_daemon(self, fault=None, env=None):
        """Restarts the client daemon with overrides, or with one fault."""
        if fault and not self.have_fault_build():
            raise Skip("the daemon with fault injection is not installed")
        env = dict(env or {})
        if fault:
            env["WGZK_FAULT"] = fault
        self.daemon("client", env, FAULT_BIN if fault else None)

    def capture_fresh(self, path, force_new_handshake=False):
        """Records an initiation that the gateway never sees: its port is blocked
        while the client sends. Leaves the client interface down, so that the
        client does not try again on its own."""
        self.must("gateway", BLOCK)
        prepare = ""
        if force_new_handshake:
            prepare = (f"wg set {IF_CL} peer {self.gw_pub} remove; "
                       f"wg set {IF_CL} peer {self.gw_pub} allowed-ips {TUNNEL_NET} endpoint {GW_IP}:{GW_PORT}; ")
        rc, ev = self.probe("client",
                            f"capture --iface {NIC} --out {path} --timeout 8 --gw-pub {self.gw_pub} & "
                            f"sleep 0.7; {PING1} >/dev/null; wait; ip link set {IF_CL} down",
                            prefix=prepare)
        self.must("gateway", UNBLOCK)
        got = [e for e in ev if e.get("event") == "captured"]
        if not got:
            raise RuntimeError("no initiation captured")
        return got[0]

    def capture_accepted(self, path):
        """Records the initiation of a handshake that succeeds."""
        rc, ev = self.probe("client",
                            f"capture --iface {NIC} --out {path} --timeout 8 --gw-pub {self.gw_pub} & "
                            f"sleep 0.7; {PING1} >/dev/null; echo ping=$?; wait")
        got = [e for e in ev if e.get("event") == "captured"]
        if not got:
            raise RuntimeError("no initiation captured")
        return got[0]


class Test:
    """Collects the checks of one test."""

    def __init__(self):
        self.checks = []

    def check(self, name, ok, **seen):
        self.checks.append({"check": name, "ok": bool(ok), "seen": seen})
        return bool(ok)

    def delta(self, name, before, after, key, expected):
        d = after[key] - before[key]
        return self.check(name, d == expected, counter=key, expected=expected, seen=d)

    def at_least(self, name, before, after, key, expected):
        d = after[key] - before[key]
        return self.check(name, d >= expected, counter=key, at_least=expected, seen=d)

    def reasons(self, name, lines, expected, count=None):
        seen = [ln.get("reason", "ok" if ln.get("result") == "ok" else "?") for ln in lines]
        ok = bool(seen) and all(r == expected for r in seen)
        if count is not None:
            ok = ok and len(seen) == count
        return self.check(name, ok, expected=expected, seen=seen[:8], lines=len(seen))

    @property
    def passed(self):
        return bool(self.checks) and all(c["ok"] for c in self.checks)


TESTS = []


def test(ident, area, variant, claim, slow=False):
    def wrap(fn):
        TESTS.append({"id": ident, "area": area, "variant": variant, "claim": claim,
                      "fn": fn, "slow": slow})
        return fn
    return wrap


# ── Positive path ─────────────────────────────────────────────────────────────

def positive(rig, t):
    g0, c0, p0 = rig.stats("gateway"), rig.stats("client"), rig.peers()
    gcur, ccur = rig.cursor("gateway"), rig.cursor("client")
    key = rig.session_key()
    t.check("first packet is answered", rig.ping())
    g1, c1, p1 = rig.stats("gateway"), rig.stats("client"), rig.peers()
    t.delta("client asked for one proof", c0, c1, "proof_requests", 1)
    t.delta("client handed down one proof", c0, c1, "proofs_set", 1)
    t.delta("gateway stored one initiation", g0, g1, "deferred", 1)
    t.delta("gateway accepted it", g0, g1, "accepted", 1)
    t.delta("nothing was rejected", g0, g1, "rejected", 0)
    t.check("the session key is a peer of the gateway now", key in p1 and key not in p0,
            peers_before=len(p0), peers_after=len(p1))
    t.check("its allowed address is one /128", p1.get(key, "").endswith("/128") and " " not in p1.get(key, ""),
            allowed_ips=p1.get(key))
    t.reasons("gateway timing line says ok", rig.timing("gateway", gcur), "ok", count=1)
    t.reasons("client timing line says ok", rig.timing("client", ccur), "ok", count=1)
    t.check("no initiation waits for a verdict", g1["pending"] == 0, pending=g1["pending"])


@test("pos-zkpq", "Positive path", "zk-pq", "A client with the credential gets a session (with ML-KEM).")
def pos_zkpq(rig, t):
    positive(rig, t)
    rc, out = rig.gw(f"wg show {IF_GW} preshared-keys | grep -c -v '(none)'")
    t.check("the peer has a preshared key", out.strip().splitlines()[0] == "1", peers_with_psk=out.strip())


@test("pos-tool", "Positive path", "zk-pq", "The same with the wg tool in place of the netlink interface.")
def pos_tool(rig, t):
    rig.daemon("gateway", {"WGZK_INSTALLER": "tool"})
    rig.client_daemon(env={"WGZK_INSTALLER": "tool"})
    positive(rig, t)
    started = [ln for ln in rig.journal("gateway", "").splitlines() if "installer=" in ln]
    t.check("the gateway daemon runs the tool", bool(started) and started[-1].endswith("installer=tool"),
            line=started[-1:] )


@test("pos-zkonly", "Positive path", "zk-only", "A client with the credential gets a session (authorization only).")
def pos_zkonly(rig, t):
    positive(rig, t)
    rc, out = rig.gw(f"wg show {IF_GW} preshared-keys | grep -c '(none)'")
    t.check("the peer has no preshared key", out.strip().splitlines()[0] == "1", peers_without_psk=out.strip())


# ── Identity ──────────────────────────────────────────────────────────────────

@test("id-connections", "Identity", "zk-pq",
      "Two connections of one client show different session keys, addresses and TLS connections.")
def id_connections(rig, t):
    gcur = rig.cursor("gateway")
    rig.must("gateway", f"(timeout 12 tcpdump -ni {NIC} -w /tmp/tls.pcap 'tcp port {TLS_PORT}' "
             ">/dev/null 2>&1 </dev/null &) ; sleep 1")
    k1 = rig.session_key()
    t.check("connection 1 works", rig.ping())
    k2 = rig.new_connection()
    t.check("connection 2 works", rig.ping())
    time.sleep(1)
    rig.gw("pkill tcpdump; sleep 0.5; true")
    p = rig.peers()
    t.check("the session keys differ", k1 != k2)
    t.check("both are peers of the gateway", k1 in p and k2 in p, peers=len(p))
    t.check("their addresses differ", p.get(k1) != p.get(k2), a1=p.get(k1), a2=p.get(k2))
    rc, out = rig.gw(f"wg show {IF_GW} preshared-keys | awk '{{print $2}}' | sort -u | wc -l")
    t.check("their preshared keys differ", out.strip() == "2", distinct_psks=out.strip())
    rc, out = rig.gw(f"wg show {IF_GW} endpoints | awk '{{print $2}}'")
    t.check("their UDP source ports differ", len(set(out.split())) == 2, endpoints=out.split())
    rc, out = rig.gw("tcpdump -nr /tmp/tls.pcap 'tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn' 2>/dev/null "
                     "| awk '{print $3}' | sort -u | wc -l")
    t.check("each handshake opened its own TCP connection", out.strip() == "2", syn_from_distinct_ports=out.strip())
    buffered = [ln for ln in rig.journal("gateway", gcur).splitlines() if "ciphertext buffered" in ln]
    t.check("two ciphertexts arrived", len(buffered) == 2, lines=len(buffered))


@test("id-rekey", "Identity", "zk-pq", "A new handshake inside a connection keeps session key and address.")
def id_rekey(rig, t):
    k1 = rig.session_key()
    t.check("first handshake works", rig.ping())
    p1, g1 = rig.peers(), rig.stats("gateway")
    # The client forgets its session; the interface key stays.
    rig.must("client", f"wg set {IF_CL} peer {rig.gw_pub} remove; "
             f"wg set {IF_CL} peer {rig.gw_pub} allowed-ips {TUNNEL_NET} endpoint {GW_IP}:{GW_PORT}")
    t.check("second handshake works", rig.ping())
    p2, g2 = rig.peers(), rig.stats("gateway")
    t.check("same session key", rig.session_key() == k1)
    t.delta("the gateway accepted a second handshake", g1, g2, "accepted", 1)
    t.check("the gateway has the same single peer", p1 == p2 and list(p2) == [k1], before=p1, after=p2)


@test("id-rekey-natural", "Identity", "zk-pq",
      "WireGuard's own re-key after two minutes passes through the proof and keeps the peer.", slow=True)
def id_rekey_natural(rig, t):
    k1 = rig.session_key()
    g0 = rig.stats("gateway")
    rc, out = rig.cl(f"ping -6 -i 1 -c 135 -W 2 {GW_ADDR} | tail -3", timeout=200)
    m = re.search(r"(\d+) packets transmitted, (\d+) received", out)
    sent, received = (int(m.group(1)), int(m.group(2))) if m else (0, 0)
    g1, p = rig.stats("gateway"), rig.peers()
    t.check("traffic kept flowing", sent == 135 and received >= 133, sent=sent, received=received)
    t.at_least("the gateway accepted the first handshake and the re-key", g0, g1, "accepted", 2)
    t.delta("nothing was rejected", g0, g1, "rejected", 0)
    t.check("the gateway has the same single peer", list(p) == [k1], peers=len(p))


@test("id-idle", "Identity", "zk-pq", "The gateway removes the peer of a connection that has gone idle.")
def id_idle(rig, t):
    rig.daemon("gateway", {"WGZK_PEER_IDLE_SECS": "10"})
    key = rig.session_key()
    t.check("the connection works", rig.ping())
    t.check("the session key is a peer", key in rig.peers())
    rig.must("client", f"ip link set {IF_CL} down")
    time.sleep(8)
    t.check("the peer is still there before the idle time has passed", key in rig.peers())
    time.sleep(16)
    peers = rig.peers()
    t.check("the peer is gone afterwards", key not in peers and not peers, peers=len(peers))
    removed = [ln for ln in rig.journal("gateway", "").splitlines() if "idle peer" in ln]
    t.check("the daemon logged the removal", bool(removed), lines=removed[-1:])
    rig.must("client", f"ip link set {IF_CL} up; ip -6 route replace {TUNNEL_NET} dev {IF_CL}")
    rig.new_connection()
    t.check("a new connection works", rig.ping())


@test("id-epochs", "Identity", "zk-only",
      "While credentials change, the gateway accepts the previous credential and the current one, and no other.")
def id_epochs(rig, t):
    old_pk = rig.must("gateway", "grep '^WGZK_PK_HEX=' /etc/wgzk.env | cut -d= -f2").strip()
    # A second credential, created in the client machine; the gateway gets its public half.
    rig.must("client", "umask 077; /vagrant/vagrant/artifacts/gen-pk | grep -E '^WGZK_(SK|PK)_HEX=' > /tmp/epoch2.env")
    new_pk = rig.must("client", "grep '^WGZK_PK_HEX=' /tmp/epoch2.env | cut -d= -f2").strip()
    t.check("the credentials differ", len(new_pk) == 64 and new_pk != old_pk)
    rig.daemon("gateway", {"WGZK_EPOCH": "2", "WGZK_PK_HEX": new_pk, "WGZK_PK_PREV_HEX": old_pk})

    g0 = rig.stats("gateway")
    t.check("previous credential, epoch 1: session", rig.ping())
    g1 = rig.stats("gateway")
    t.delta("accepted", g0, g1, "accepted", 1)

    rig.must("client", "mkdir -p /etc/systemd/system/wgzk.service.d; umask 077; "
             "(grep '^WGZK_SK_HEX=' /tmp/epoch2.env; echo WGZK_EPOCH=2) > /etc/wgzk-test.env; "
             "printf '[Service]\nEnvironmentFile=/etc/wgzk-test.env\n' > /etc/systemd/system/wgzk.service.d/test.conf; "
             "systemctl daemon-reload; systemctl restart wgzk; sleep 1; systemctl is-active wgzk")
    rig.new_connection()
    t.check("current credential, epoch 2: session", rig.ping())
    g2 = rig.stats("gateway")
    t.delta("accepted", g1, g2, "accepted", 1)

    # The gateway moves on: epoch 3 with the second credential as the previous one.
    # The first credential is two epochs old now.
    rig.must("client", "umask 077; /vagrant/vagrant/artifacts/gen-pk | grep -E '^WGZK_(SK|PK)_HEX=' > /tmp/epoch3.env")
    third_pk = rig.must("client", "grep '^WGZK_PK_HEX=' /tmp/epoch3.env | cut -d= -f2").strip()
    rig.daemon("gateway", {"WGZK_EPOCH": "3", "WGZK_PK_HEX": third_pk, "WGZK_PK_PREV_HEX": new_pk})
    rig.new_connection()
    t.check("second credential as the previous one: session", rig.ping())
    g3 = rig.stats("gateway")
    rig.client_daemon()  # back to the first credential, epoch 1
    gcur = rig.cursor("gateway")
    rig.new_connection()
    t.check("first credential, two epochs old: no session", not rig.ping())
    time.sleep(0.5)
    g4 = rig.stats("gateway")
    t.delta("rejected", g3, g4, "rejected", 1)
    t.delta("not accepted", g3, g4, "accepted", 0)
    t.reasons("reason in the gateway log", rig.timing("gateway", gcur), "proof", count=1)


# ── Refusals ──────────────────────────────────────────────────────────────────

def refused(rig, t, reason, expect_deferred=1):
    """The client tries a handshake that the gateway must refuse for `reason`."""
    g0, p0, gcur = rig.stats("gateway"), rig.peers(), rig.cursor("gateway")
    key = rig.new_connection()
    t.check("the client gets no answer", not rig.ping(wait=2))
    time.sleep(0.5)
    g1, p1 = rig.stats("gateway"), rig.peers()
    t.delta("gateway stored the initiation", g0, g1, "deferred", expect_deferred)
    t.delta("gateway rejected it", g0, g1, "rejected", expect_deferred)
    t.delta("gateway accepted nothing", g0, g1, "accepted", 0)
    t.check("no peer was created", p1 == p0 and key not in p1, peers_before=len(p0), peers_after=len(p1))
    t.reasons("reason in the gateway log", rig.timing("gateway", gcur), reason, count=expect_deferred)
    t.check("the client has no session", rig.client_handshake_age() is None)


def fault_test(ident, area, variant, fault, reason, claim):
    @test(ident, area, variant, claim)
    def run(rig, t):
        rig.client_daemon(fault=fault)
        refused(rig, t, reason)
    return run


fault_test("auth-bad-proof", "Authorisation", "zk-only", "bad_proof", "proof",
           "An invalid proof creates no peer.")
fault_test("auth-other-key", "Authorisation", "zk-only", "other_key", "proof",
           "A proof computed for another session key creates no peer.")
fault_test("auth-other-gw", "Authorisation", "zk-only", "other_gw", "proof",
           "A proof computed for another gateway creates no peer.")
fault_test("auth-other-epoch", "Authorisation", "zk-only", "other_epoch", "proof",
           "A proof computed for an epoch that the gateway does not accept creates no peer.")
fault_test("pq-skip-ct", "PQ enforcement", "zk-pq", "skip_ct", "no_ct",
           "Without a ciphertext there is no session, although the proof is valid.")
fault_test("pq-other-nonce", "PQ enforcement", "zk-pq", "other_nonce_ct", "no_ct",
           "A ciphertext that arrived for another nonce does not count.")
fault_test("pq-flip-ct", "PQ enforcement", "zk-pq", "flip_ct", "proof",
           "A ciphertext that differs from the one the proof is bound to is refused.")


@test("auth-wrong-credential", "Authorisation", "zk-only",
      "A client with another group secret creates no peer.")
def auth_wrong_credential(rig, t):
    # A valid scalar that is not the group secret: the secret of the test vector in zk.rs.
    rig.client_daemon(env={"WGZK_SK_HEX": "4731bcefd3f3791c92a34f200ba53d34ec23fba43359c942acc6de359f62c50c"})
    refused(rig, t, "proof")


@test("auth-replay", "Authorisation", "zk-pq", "A recorded initiation that is sent again creates nothing.")
def auth_replay(rig, t):
    cap = rig.capture_accepted("/tmp/accepted.bin")
    t.check("the recorded handshake succeeded", rig.client_handshake_age() is not None)
    t.check("the tool computes the same MAC as the kernel", cap.get("mac1_ok") is True)
    g0, p0, gcur = rig.stats("gateway"), rig.peers(), rig.cursor("gateway")
    rc, ev = rig.probe("client", f"send --in /tmp/accepted.bin --dst {GW_IP}:{GW_PORT} --count 3 --rate 5 --listen 1.5")
    sent = [e for e in ev if e.get("event") == "sent"][0]
    g1, p1 = rig.stats("gateway"), rig.peers()
    t.delta("gateway stored the three copies", g0, g1, "deferred", 3)
    t.delta("gateway rejected the three copies", g0, g1, "rejected", 3)
    t.delta("gateway accepted nothing", g0, g1, "accepted", 0)
    t.check("no answer reached the sender", sent["responses"] == 0, responses=sent["responses"])
    t.check("the peers did not change", p0 == p1)
    t.reasons("reason in the gateway log", rig.timing("gateway", gcur), "replay", count=3)


@test("auth-transplant", "Authorisation", "zk-only",
      "A proof copied from the wire into an initiation with another key creates no peer.")
def auth_transplant(rig, t):
    cap = rig.capture_fresh("/tmp/fresh.bin")
    victim = rig.session_key()
    rig.must("client", "systemctl stop wgzk; umask 077; wg genkey | tee /tmp/atk.key | wg pubkey > /tmp/atk.pub; "
             "ip link add wgatk type wireguard; wg set wgatk private-key /tmp/atk.key "
             f"peer {rig.gw_pub} allowed-ips {TUNNEL_NET} endpoint {GW_IP}:{GW_PORT}; "
             "ip -6 addr add $(wg-zk-daemon derive-addr $(cat /tmp/atk.pub))/128 dev wgatk; "
             f"ip link set wgatk mtu 1380 up; ip -6 route replace {TUNNEL_NET} dev wgatk")
    attacker = rig.must("client", "cat /tmp/atk.pub").strip()
    g0, p0, gcur = rig.stats("gateway"), rig.peers(), rig.cursor("gateway")
    rc, ev = rig.probe("client", f"proof --iface wgatk --in /tmp/fresh.bin --seconds 8 & sleep 0.7; {PING1}; wait")
    set_ = [e for e in ev if e.get("event") == "proof_set"]
    time.sleep(0.5)
    g1, p1 = rig.stats("gateway"), rig.peers()
    t.check("the kernel took the copied proof", bool(set_) and set_[0]["errno"] == 0, events=ev[-2:])
    t.check("it went out under the attacker's key", bool(set_) and set_[0].get("local_pub") == attacker
            and attacker != victim)
    t.check("the proof is the recorded one", bool(set_) and set_[0].get("nonce4") == cap["nonce4"])
    t.delta("gateway stored the initiation", g0, g1, "deferred", 1)
    t.delta("gateway rejected it", g0, g1, "rejected", 1)
    t.check("no peer was created", p1 == p0 and attacker not in p1, peers=len(p1))
    t.reasons("reason in the gateway log", rig.timing("gateway", gcur), "proof", count=1)


# ── PQ enforcement without fault injection ───────────────────────────────────

def client_aborts(rig, t, reason):
    """The client daemon must give up before it hands a proof to the kernel."""
    g0, c0, p0, ccur = rig.stats("gateway"), rig.stats("client"), rig.peers(), rig.cursor("client")
    rig.new_connection()
    t.check("the client gets no answer", not rig.ping(wait=3))
    g1, c1 = rig.stats("gateway"), rig.stats("client")
    t.at_least("the kernel asked for a proof", c0, c1, "proof_requests", 1)
    t.delta("the daemon handed down none", c0, c1, "proofs_set", 0)
    t.delta("no initiation reached the gateway", g0, g1, "deferred", 0)
    t.check("no peer was created", rig.peers() == p0)
    t.reasons("reason in the client log", rig.timing("client", ccur), reason)
    t.check("the client has no session", rig.client_handshake_age() is None)


@test("pq-failed-tls", "PQ enforcement", "zk-pq",
      "If the ciphertext cannot be delivered, the client sends no initiation.")
def pq_failed_tls(rig, t):
    rig.client_daemon(env={"MLKEM_SERVER_ADDR": f"{GW_IP}:51999"})
    client_aborts(rig, t, "tls_connect")


@test("pq-wrong-pin", "TLS", "zk-pq",
      "If the certificate of the gateway does not match the fingerprint, the client sends nothing.")
def pq_wrong_pin(rig, t):
    rig.client_daemon(env={"MLKEM_CERT_FP": "00" * 32})
    gcur = rig.cursor("gateway")
    client_aborts(rig, t, "tls_connect")
    buffered = [ln for ln in rig.journal("gateway", gcur).splitlines() if "ciphertext buffered" in ln]
    t.check("the gateway received no ciphertext", not buffered, lines=len(buffered))


@test("pq-failed-psk", "PQ enforcement", "zk-pq",
      "If the client cannot install its key, it sends no initiation.")
def pq_failed_psk(rig, t):
    rig.must("client", "mkdir -p /opt/wgzk-test/bin; printf '#!/bin/sh\\nexit 1\\n' > /opt/wgzk-test/bin/wg; "
             "chmod +x /opt/wgzk-test/bin/wg")
    # The installer that runs the wg tool, and a wg tool that fails.
    rig.client_daemon(env={"WGZK_INSTALLER": "tool", "PATH": "/opt/wgzk-test/bin:/usr/sbin:/usr/bin:/sbin:/bin"})
    client_aborts(rig, t, "psk")


@test("pq-no-psk", "PQ enforcement", "zk-pq",
      "A client that does not use the ML-KEM secret gets no session, although its proof is valid.")
def pq_no_psk(rig, t):
    rig.client_daemon(fault="no_psk")
    g0 = rig.stats("gateway")
    rig.new_connection()
    t.check("the client gets no answer it can use", not rig.ping(wait=2))
    g1 = rig.stats("gateway")
    t.delta("the gateway accepted the proof and the ciphertext", g0, g1, "accepted", 1)
    t.check("the client has no session", rig.client_handshake_age() is None)
    rc, out = rig.gw(f"wg show {IF_GW} transfer | awk '{{print $2}}'; "
                     f"wg show {IF_GW} latest-handshakes | awk '{{print $2}}'")
    received, confirmed = out.split()[:2]
    t.check("the gateway received the initiation and nothing else", received == "244", received_bytes=received)
    t.check("no session was confirmed at the gateway", confirmed == "0", latest_handshake=confirmed)


# ── TLS ───────────────────────────────────────────────────────────────────────

@test("tls-12-refused", "TLS", "zk-pq", "The gateway refuses a client that offers TLS 1.2.")
def tls_12(rig, t):
    gcur = rig.cursor("gateway")
    rc, ev = rig.probe("client", f"tls --dst {GW_IP}:{TLS_PORT} --count 3 --tls12")
    done = [e for e in ev if e.get("event") == "tls_done"][0]
    t.check("no TLS 1.2 session", done["delivered"] == 0 and done["refused"] == 3, **done)
    rc, ev = rig.probe("client", f"tls --dst {GW_IP}:{TLS_PORT} --count 3")
    done = [e for e in ev if e.get("event") == "tls_done"][0]
    t.check("control: TLS 1.3 from the same tool is accepted", done["delivered"] == 3, **done)
    buffered = [ln for ln in rig.journal("gateway", gcur).splitlines() if "ciphertext buffered" in ln]
    t.check("only the three TLS 1.3 messages were stored", len(buffered) == 3, lines=len(buffered))


# ── Kernel ────────────────────────────────────────────────────────────────────

@test("k-unprivileged", "Kernel", "zk-only", "A process without privileges cannot send a verdict.")
def k_unprivileged(rig, t):
    rig.capture_fresh("/tmp/fresh.bin")
    # No daemon answers; the test does, by hand, and needs more than five seconds.
    rig.must("gateway", "systemctl stop wgzk; echo 60000 > /sys/module/wireguard/parameters/pending_timeout_ms")
    g0 = rig.stats("gateway")
    rig.probe("client", f"send --in /tmp/fresh.bin --dst {GW_IP}:{GW_PORT} --listen 0.2")
    rc, out = rig.gw("awk 'NR>2 {print $1; exit}' /sys/kernel/debug/wgzk/pending")
    pending_id = out.strip()
    t.check("an initiation waits for its verdict", pending_id.isdigit(), pending_id=pending_id)
    rc, ev = rig.probe("gateway", f"verdict --pending-id {pending_id or 0} --result 1", prefix="sudo -u nobody ")
    v = ([e for e in ev if e.get("event") == "verdict"] or [{}])[0]
    t.check("refused for the unprivileged user", v.get("errno") == 1 and v.get("uid") == 65534, **v)
    g1 = rig.stats("gateway")
    t.check("the initiation still waits", g1["pending"] == 1 and g1["accepted"] == g0["accepted"], pending=g1["pending"])
    rc, ev = rig.probe("gateway", f"verdict --pending-id {pending_id or 0} --result 0")
    v = ([e for e in ev if e.get("event") == "verdict"] or [{}])[0]
    t.check("control: accepted from root", v.get("errno") == 0 and v.get("uid") == 0, **v)
    g2 = rig.stats("gateway")
    t.delta("the verdict of root took effect", g1, g2, "rejected", 1)
    t.check("nothing waits any more", g2["pending"] == 0, pending=g2["pending"])
    rc, ev = rig.probe("gateway", "verdict --pending-id 987654321 --result 1")
    v = ([e for e in ev if e.get("event") == "verdict"] or [{}])[0]
    t.check("a verdict for an unknown id is an error", v.get("errno") == 2, **v)


@test("k-same-index", "Kernel", "zk-only",
      "Two stored initiations with the same sender index each receive their own verdict.")
def k_same_index(rig, t):
    cap = rig.capture_fresh("/tmp/fresh.bin")
    key = rig.session_key()
    g0, gcur = rig.stats("gateway"), rig.cursor("gateway")
    rc, ev = rig.probe("client", f"send --in /tmp/fresh.bin --dst {GW_IP}:{GW_PORT} --count 2 --listen 1.5")
    sent = [e for e in ev if e.get("event") == "sent"][0]
    g1, lines = rig.stats("gateway"), rig.timing("gateway", gcur)
    t.delta("both were stored", g0, g1, "deferred", 2)
    t.delta("one was accepted", g0, g1, "accepted", 1)
    t.delta("one was rejected", g0, g1, "rejected", 1)
    t.check("exactly one answer was sent", sent["responses"] == 1, responses=sent["responses"])
    ids = sorted(ln.get("pending_id") for ln in lines)
    results = sorted(ln.get("reason", ln.get("result")) for ln in lines)
    t.check("two verdicts under two ids", len(set(ids)) == 2 and results == ["ok", "replay"], ids=ids, results=results)
    t.check("same sender index, same nonce", len({ln.get("nonce_prefix") for ln in lines}) == 1
            and sent["sender_index"] == cap["sender_index"])
    t.check("one peer exists, the session key", list(rig.peers()) == [key])


@test("k-locks", "Kernel", "zk-pq",
      "After 1,000 stored initiations that time out or are rejected, the gateway can change its key, "
      "remove the interface and unload the module.")
def k_locks(rig, t):
    rig.capture_accepted("/tmp/accepted.bin")
    g0 = rig.stats("gateway")
    rig.must("gateway", "systemctl stop wgzk")
    rig.probe("client", f"send --in /tmp/accepted.bin --dst {GW_IP}:{GW_PORT} --count 500 --rate 60 --listen 0.2")
    time.sleep(7)
    g1 = rig.stats("gateway")
    t.delta("500 were stored without a daemon", g0, g1, "deferred", 500)
    t.delta("500 timed out", g0, g1, "expired", 500)
    rig.must("gateway", "systemctl start wgzk; sleep 1.5")
    rig.probe("client", f"send --in /tmp/accepted.bin --dst {GW_IP}:{GW_PORT} --count 500 --rate 60 --listen 1")
    time.sleep(1)
    g2 = rig.stats("gateway")
    t.delta("500 more were stored", g1, g2, "deferred", 500)
    t.delta("500 were rejected", g1, g2, "rejected", 500)
    t.check("nothing waits", g2["pending"] == 0, pending=g2["pending"])
    rc, out = rig.gw(f"umask 077; wg genkey > /tmp/other.key; timeout 5 wg set {IF_GW} private-key /tmp/other.key; echo rc=$?")
    t.check("the key of the interface can be changed", "rc=0" in out, out=out.strip())
    rc, out = rig.gw(f"systemctl stop wgzk; timeout 20 ip link del {IF_GW}; echo rc=$?")
    t.check("the interface can be removed", "rc=0" in out, out=out.strip())
    rc, out = rig.gw("timeout 20 rmmod wireguard; echo rc=$?; dmesg | grep -c -E 'BUG|WARNING|Call Trace|unregister_netdevice: waiting'")
    lines = out.strip().splitlines()
    t.check("the module can be unloaded", "rc=0" in lines, out=lines)
    t.check("the kernel log has no warning", lines[-1] == "0", matching_lines=lines[-1])


@test("k-legacy", "Legacy path", "zk-only", "An initiation without proof is dropped.")
def k_legacy(rig, t):
    t.check("a connection exists", rig.ping())
    rig.capture_fresh("/tmp/fresh.bin", force_new_handshake=True)
    g0 = rig.stats("gateway")
    send = f"send --in /tmp/fresh.bin --plain --gw-pub {rig.gw_pub} --dst {GW_IP}:{GW_PORT} --listen 1"
    rc, ev = rig.probe("client", send)
    sent = [e for e in ev if e.get("event") == "sent"][0]
    g1 = rig.stats("gateway")
    t.check("the packet is a plain initiation", sent["bytes"] == 148 and sent["plain"] is True, bytes=sent["bytes"])
    t.delta("the gateway counted it as dropped", g0, g1, "legacy_dropped", 1)
    t.delta("it was not stored", g0, g1, "deferred", 0)
    t.check("no answer", sent["responses"] == 0, responses=sent["responses"])
    rig.must("gateway", "echo 0 > /sys/module/wireguard/parameters/require_zk")
    rc, ev = rig.probe("client", send)
    rig.must("gateway", "echo 1 > /sys/module/wireguard/parameters/require_zk")
    sent = [e for e in ev if e.get("event") == "sent"][0]
    g2 = rig.stats("gateway")
    t.check("control: with the switch off the same packet is answered", sent["responses"] == 1,
            responses=sent["responses"])
    t.delta("control: not counted as dropped", g1, g2, "legacy_dropped", 0)


# ── Bounded state ─────────────────────────────────────────────────────────────

def daemon_rss(rig):
    rc, out = rig.gw("ps -o rss= -C wg-zk-daemon | head -1")
    return int(out.strip() or 0)


@test("b-initiations", "Bounded state", "zk-only",
      "10,000 initiations that cannot be verified leave the table, the memory and the peers bounded.")
def b_initiations(rig, t):
    rig.capture_accepted("/tmp/accepted.bin")
    g0, p0 = rig.stats("gateway"), rig.peers()
    rig.sample("gateway", f"head -1 {STATS}", 0.1, "/tmp/pending.log")
    flood = (f"send --in /tmp/accepted.bin --mutate s --gw-pub {rig.gw_pub} "
             f"--dst {GW_IP}:{GW_PORT} --count 5000 --rate 2500 --listen 1")
    # First half without a daemon: nothing takes entries out of the table but time.
    rig.must("gateway", "systemctl stop wgzk")
    rc, ev = rig.probe("client", flood)
    first = [e for e in ev if e.get("event") == "sent"][0]
    time.sleep(7)
    # Second half with the daemon, which has to reject every one of them.
    rig.must("gateway", "systemctl start wgzk; sleep 1.5")
    rss0 = daemon_rss(rig)
    rc, ev = rig.probe("client", flood)
    second = [e for e in ev if e.get("event") == "sent"][0]
    time.sleep(7)
    g1, p1, rss1 = rig.stats("gateway"), rig.peers(), daemon_rss(rig)
    rig.stop_sampling("gateway")
    out = rig.must("gateway", "awk '{ if ($2 > m) m = $2 } END { print m + 0 }' /tmp/pending.log; "
                   "cat /sys/module/wireguard/parameters/pending_max")
    peak, bound = (int(x) for x in out.split()[-2:])
    stored = g1["deferred"] - g0["deferred"]
    t.check("10,000 packets were sent", first["count"] + second["count"] == 10000,
            seconds=[first["seconds"], second["seconds"]],
            cookie_replies=[first["cookie_replies"], second["cookie_replies"]])
    t.check("the table filled and stayed within its bound", 0 < peak <= bound, peak=peak, bound=bound)
    t.check("every stored initiation was rejected or timed out",
            stored == (g1["rejected"] - g0["rejected"]) + (g1["expired"] - g0["expired"]), stored=stored,
            rejected=g1["rejected"] - g0["rejected"], expired=g1["expired"] - g0["expired"],
            refused_full=g1["refused_full"] - g0["refused_full"])
    t.delta("nothing was accepted", g0, g1, "accepted", 0)
    t.check("nothing waits afterwards", g1["pending"] == 0, pending=g1["pending"])
    t.check("the peers did not change", p0 == p1, peers=len(p1))
    t.check("the daemon did not grow by more than 16 MB", rss1 - rss0 < 16 * 1024, rss_before_kb=rss0, rss_after_kb=rss1)
    rig.new_connection()
    t.check("a client with the credential still gets a session", rig.ping(wait=3))


@test("b-ciphertexts", "Bounded state", "zk-pq",
      "10,000 side-channel messages that no initiation follows leave the memory and the peers bounded.")
def b_ciphertexts(rig, t):
    # A buffer small enough that the flood of this test bed fills it for certain.
    bound, ttl = 256, 5
    rig.daemon("gateway", {"WGZK_CT_BUFFER_MAX": str(bound), "WGZK_CT_TTL_MS": str(ttl * 1000)})
    g0, p0, rss0, gcur = rig.stats("gateway"), rig.peers(), daemon_rss(rig), rig.cursor("gateway")
    rig.sample("gateway", "ps -o rss= -C wg-zk-daemon | head -1", 0.5, "/tmp/rss.log")
    rc, ev = rig.probe("client", f"tls --dst {GW_IP}:{TLS_PORT} --count 10000", timeout=900)
    done = [e for e in ev if e.get("event") == "tls_done"][0]
    rig.stop_sampling("gateway")
    out = rig.must("gateway", "awk '{ if ($1 > m) m = $1 } END { print m + 0 }' /tmp/rss.log")
    peak = int(out.split()[-1])
    g1, p1 = rig.stats("gateway"), rig.peers()
    log = rig.journal("gateway", gcur)
    stored, refused_ = log.count("ciphertext buffered"), log.count("ciphertext refused")
    t.check("10,000 messages were delivered", done["delivered"] == 10000, **done)
    t.check("every message was stored or refused", stored + refused_ == 10000, stored=stored, refused=refused_)
    t.check("the buffer refused messages when it was full", refused_ > 0, refused=refused_)
    # A slot is free again when its entry expires, so at most one bufferful per lifetime.
    most = bound * (int(done["seconds"] / ttl) + 2)
    t.check("it stored no more than its bound allows", stored <= most, stored=stored, at_most=most,
            bound=bound, lifetime_seconds=ttl, flood_seconds=done["seconds"])
    t.check("the daemon stayed below 64 MB", 0 < peak < 64 * 1024, rss_before_kb=rss0, rss_peak_kb=peak)
    t.delta("no initiation was stored", g0, g1, "deferred", 0)
    t.check("the peers did not change", p0 == p1, peers=len(p1))
    time.sleep(6)
    rig.new_connection()
    t.check("a client with the credential still gets a session", rig.ping(wait=3))


@test("b-connections", "Bounded state", "zk-pq",
      "Connections that send nothing are closed after the handshake timeout.")
def b_connections(rig, t):
    rc, ev = rig.probe("client", f"tls --dst {GW_IP}:{TLS_PORT} --count 300 --hold 4")
    hold = [e for e in ev if e.get("event") == "tls_hold"][0]
    t.check("300 connections were opened", hold["opened"] == 300, **hold)
    t.check("none is open after the timeout", hold["open_after_hold"] == 0, open_after_hold=hold["open_after_hold"])
    rig.new_connection()
    t.check("a client with the credential still gets a session", rig.ping(wait=3))


# ── Runner ────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("tests", nargs="*", help="test ids; default: all")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--skip-slow", action="store_true")
    a = ap.parse_args()
    if a.list:
        for x in TESTS:
            print(f"{x['id']:22} {x['variant']:8} {x['area']:16} {x['claim']}")
        return 0
    unknown = set(a.tests) - {x["id"] for x in TESTS}
    if unknown:
        sys.exit(f"unknown tests: {', '.join(sorted(unknown))}")
    chosen = [x for x in TESTS if (not a.tests or x["id"] in a.tests) and not (a.skip_slow and x["slow"])]

    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    outdir = os.path.join(ROOT, "bench/results/acceptance", stamp)
    os.makedirs(outdir)
    rig = Rig(outdir)
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True).stdout
    manifest = open(os.path.join(ROOT, "vagrant/artifacts/MANIFEST")).read()

    results = []
    for x in chosen:
        t, status, error = Test(), "fail", ""
        started = time.time()
        with open(os.path.join(outdir, x["id"] + ".log"), "w") as log:
            rig.log = log
            try:
                rig.provision(x["variant"])
                x["fn"](rig, t)
                status = "pass" if t.passed else "fail"
            except Skip as e:
                status, error = "skipped", str(e)
            except Exception as e:  # a broken test is a failed test
                error = f"{type(e).__name__}: {e}"
            rig.log = None
        r = {"id": x["id"], "area": x["area"], "variant": x["variant"], "claim": x["claim"], "status": status,
             "error": error, "seconds": round(time.time() - started, 1), "checks": t.checks}
        results.append(r)
        failed = [c["check"] for c in t.checks if not c["ok"]]
        print(f"{status.upper():8} {x['id']:22} {r['seconds']:6.1f}s  "
              f"{len(t.checks) - len(failed)}/{len(t.checks)} checks"
              + (f"  FAILED: {failed}" if failed else "") + (f"  {error}" if error else ""), flush=True)
        with open(os.path.join(outdir, "results.jsonl"), "a") as f:
            f.write(json.dumps(r, sort_keys=True) + "\n")

    count = {s: sum(r["status"] == s for r in results) for s in ("pass", "fail", "skipped")}
    with open(os.path.join(outdir, "summary.md"), "w") as f:
        f.write(f"# Acceptance tests, {stamp}\n\n")
        f.write(f"Commit `{commit}`, {len(dirty.splitlines())} files changed in the working tree. "
                f"Test bed: {rig.bed.rig['name']}.\n\n")
        f.write("Artefacts under test:\n\n```\n" + manifest + "```\n\n")
        f.write(f"Passed {count['pass']}, failed {count['fail']}, skipped {count['skipped']}.\n\n")
        f.write("| Test | Area | Variant | Result | Checks | Claim |\n|---|---|---|---|---|---|\n")
        for r in results:
            ok = sum(c["ok"] for c in r["checks"])
            f.write(f"| `{r['id']}` | {r['area']} | {r['variant']} | {r['status']} | "
                    f"{ok}/{len(r['checks'])} | {r['claim']} |\n")
        for r in results:
            if r["status"] == "pass":
                continue
            f.write(f"\n## `{r['id']}`: {r['status']}\n\n")
            if r["error"]:
                f.write(r["error"] + "\n\n")
            for c in r["checks"]:
                if not c["ok"]:
                    f.write(f"- {c['check']}: `{json.dumps(c['seen'], sort_keys=True)}`\n")
    rig.bed.close()
    print(f"\npassed {count['pass']}, failed {count['fail']}, skipped {count['skipped']}; results in {outdir}")
    return 1 if count["fail"] else 0


if __name__ == "__main__":
    sys.exit(main())
