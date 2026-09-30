#!/usr/bin/env python3
"""M-7: concurrency of N simultaneous client interfaces against one gateway.

Runs on the host, in the repository root, with both machines up:

    python3 bench/concurrency.py --n 2 --rounds 5 --out bench/results/r1/NAME

Provisions N client interfaces (wgc0..wgc(N-1)), one wg-zk-daemon instance per interface
(vagrant/03-client-m7.sh; see its header for why one daemon per interface needs no daemon
change, and why the routing rule is per output interface, not per source address). Each
round, every interface gets a fresh session key and address (bench/guest/concurrent_trials.py),
then all N send one echo request at the same moment.

Output directory: trials.jsonl (one record per client per round), summary.json, setup.log.
See bench/latency.py for the single-interface measurement this borrows its setup/timing
structure from; unlike it, this script does not take a CPU-time measurement (M-2/N-3 is
about steady single-interface load, not this experiment).

Limits worth respecting, from the protocol (docs/protocol-r1.md) and the daemon's own
settings.rs: at most 256 TLS connections in flight at the gateway at once, so n must not
exceed that; the gateway holds a peer for up to 300s after its last use, and at most 4096 at
once, so rounds * n must stay under 4096 within any 300s stretch of the run.
"""

import argparse
import json
import os
import statistics
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rig as rigmod  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAX_INFLIGHT = 256
MAX_PEERS = 4096
PEER_IDLE_S = 300


class Rig:
    """The machines under test, and the log of what was done to them."""

    def __init__(self, outdir):
        self.bed = rigmod.Bed("wgzk", workdir=outdir)
        self.log = open(os.path.join(outdir, "setup.log"), "a")

    def must(self, vm, script, timeout=300):
        rc, out, err = self.bed.run(vm, script, timeout)
        self.log.write(f"\n$ [{vm}] {script}\n{out}{err}[exit {rc}]\n")
        self.log.flush()
        if rc != 0:
            sys.exit(f"step failed in {vm} (exit {rc}): {script}\n{out}{err}")
        return out

    def cursor(self, vm, unit):
        out = self.must(vm, f"journalctl -u {unit} -n 1 --show-cursor -o cat --no-pager | tail -1")
        return out.split("cursor: ", 1)[1].strip() if "cursor: " in out else ""

    def timing(self, vm, unit, cursor):
        """[timing] lines of `unit` since `cursor`, with the time the journal received them.
        Same parsing as bench/latency.py's Rig.timing, parameterized by unit instead of the
        fixed "wgzk": each client interface is its own systemd unit instance here."""
        after = f"--after-cursor='{cursor}'" if cursor else ""
        out = self.must(vm, f"journalctl -u {unit} -o json --no-pager {after} | grep -F '[timing]' || true")
        lines = []
        for raw in out.splitlines():
            try:
                rec = json.loads(raw)
            except ValueError:
                continue
            msg = rec.get("MESSAGE", "")
            if not isinstance(msg, str) or not msg.startswith("[timing] "):
                continue
            d = dict(kv.split("=", 1) for kv in msg.split()[1:] if "=" in kv)
            d["journal_us"] = int(rec["__REALTIME_TIMESTAMP"])
            lines.append(d)
        return lines


def setup(rig, n, variant, gw_ip):
    rig.bed.push_share()
    rig.must("gateway", "rm -rf /etc/systemd/system/wgzk.service.d /etc/wgzk-test.env; "
             "bash /vagrant/vagrant/02-load-module.sh && "
             f"WGZK_VARIANT={variant} bash /vagrant/vagrant/03-gateway.sh")
    rig.must("client", f"GW_IP={gw_ip} PEER_IP={gw_ip} WGZK_VARIANT={variant} WGZK_M7_N={n} "
             "bash /vagrant/vagrant/03-client-m7.sh", timeout=600)


def describe(values):
    v = sorted(x for x in values if x is not None)
    if not v:
        return {"n": 0}
    return {"n": len(v), "min": v[0], "median": statistics.median(v), "max": v[-1],
            "mean": statistics.fmean(v)}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--n", type=int, required=True, help="number of concurrent client interfaces")
    ap.add_argument("--rounds", type=int, default=1)
    ap.add_argument("--steady", type=int, default=5)
    ap.add_argument("--gap", type=float, default=0.3)
    ap.add_argument("--wait", type=int, default=5)
    ap.add_argument("--variant", default="zk-pq", choices=["zk-pq", "zk-only"])
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    if a.n > MAX_INFLIGHT:
        sys.exit(f"--n {a.n} exceeds the gateway's {MAX_INFLIGHT} simultaneous TLS connections")
    if a.n * a.rounds > MAX_PEERS:
        print(f"warning: {a.n} * {a.rounds} rounds = {a.n * a.rounds} peers; the gateway holds "
              f"at most {MAX_PEERS} for up to {PEER_IDLE_S}s idle each; keep the run under "
              f"{PEER_IDLE_S}s or expect early peers to be reclaimed", file=sys.stderr)

    os.makedirs(a.out, exist_ok=True)
    trials_file = os.path.join(a.out, "trials.jsonl")
    summary_file = os.path.join(a.out, "summary.json")
    if os.path.exists(trials_file):
        sys.exit(f"{a.out} holds trials already; use another directory")

    rig = Rig(a.out)
    load_before = rig.bed.host_load()
    gw_ip = rig.bed.gw_ip
    setup(rig, a.n, a.variant, gw_ip)

    gw_pub = open(os.path.join(ROOT, "vagrant/keys/public_right")).read().strip()
    units = [f"wgzk-m7@wgc{k}.service" for k in range(a.n)]
    rig.must("client", f"ping -n -c 3 -W 2 {gw_ip} >/dev/null; "
             "ping -6 -n -c 3 -W 5 fd57:475a:4b00::1 -I wgc0 >/dev/null || true")
    time.sleep(1)
    gw_cursor = rig.cursor("gateway", "wgzk")
    client_cursors = {u: rig.cursor("client", u) for u in units}

    started = time.time()
    trials = []
    cmd = (f"python3 /vagrant/bench/guest/concurrent_trials.py --n {a.n} --rounds {a.rounds} "
           f"--steady {a.steady} --gap {a.gap} --wait {a.wait} --label wgzk-m7")
    with rig.bed.popen("client", cmd) as p:
        for line in p.stdout:
            if line.startswith("{"):
                trials.append(json.loads(line))
                if len(trials) % max(1, a.n * 10) == 0:
                    print(f"  {len(trials)}/{a.n * a.rounds} client-rounds", flush=True)
        err = p.stderr.read()
    if p.returncode != 0:
        sys.exit(f"the trial loop failed (exit {p.returncode}):\n{err}")

    time.sleep(1)
    gateway = {}
    for ln in rig.timing("gateway", "wgzk", gw_cursor):
        gateway.setdefault(ln.get("nonce_prefix"), []).append(ln)
    client_by_unit = {u: rig.timing("client", u, client_cursors[u]) for u in units}

    for t in trials:
        unit = f"wgzk-m7@{t['iface']}.service"
        lo, hi = t["start_ns"] // 1000, t["end_ns"] // 1000
        t["client"] = [ln for ln in client_by_unit[unit] if lo <= ln["journal_us"] <= hi]
        t["gateway"] = [g for ln in t["client"] for g in gateway.get(ln.get("nonce_prefix"), [])]
        steady = [x for x in t["steady_rtt_ms"] if x is not None]
        t["steady_median_ms"] = statistics.median(steady) if steady else None
        t["handshake_ms"] = (t["first_rtt_ms"] - t["steady_median_ms"]
                             if t["ok"] and steady else None)

    with open(trials_file, "w") as f:
        for t in trials:
            f.write(json.dumps(t, sort_keys=True) + "\n")

    ok = [t for t in trials if t["handshake_ms"] is not None]
    by_n = {}
    for t in trials:
        by_n.setdefault(t["n"], []).append(t)
    summary = {
        "system": "wgzk-m7", "variant": a.variant, "n": a.n, "rounds": a.rounds,
        "trials": len(trials), "succeeded": len(ok), "failed": len(trials) - len(ok),
        "handshake_ms": describe([t["handshake_ms"] for t in ok]),
        "first_rtt_ms": describe([t["first_rtt_ms"] for t in ok]),
        "by_n": {str(n): {"trials": len(ts), "succeeded": sum(t["handshake_ms"] is not None for t in ts)}
                for n, ts in by_n.items()},
        "host_load": {"before": load_before["loadavg"], "after": rig.bed.host_load()["loadavg"],
                     "threads": load_before["threads"]},
        "seconds": round(time.time() - started, 1),
        "commit": subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                                 text=True).stdout.strip(),
        "dirty_files": len(subprocess.run(["git", "status", "--porcelain"], cwd=ROOT,
                                          capture_output=True, text=True).stdout.splitlines()),
    }
    one = [t for t in ok if len(t["client"]) == 1 and len(t["gateway"]) == 1]
    summary["trials_with_exactly_one_handshake"] = len(one)
    for side, keys in (("client", ("zk_us", "encap_us", "tls_us", "write_us", "psk_us", "tail_us", "total_us")),
                       ("gateway", ("wait_ct_us", "verify_us", "decap_us", "peer_us", "total_us"))):
        summary[side + "_ms"] = {k[:-3]: describe([int(t[side][0][k]) / 1000 for t in one]) for k in keys}
    with open(summary_file, "w") as f:
        json.dump(summary, f, indent=2, sort_keys=True)
        f.write("\n")
    rig.log.close()
    rig.bed.close()

    h = summary["handshake_ms"]
    print(f"wgzk-m7 n={a.n} rounds={a.rounds}: {summary['succeeded']}/{summary['trials']} "
          f"handshakes; latency median {h.get('median', float('nan')):.2f} ms; host load "
          f"{summary['host_load']['before'][0]} to {summary['host_load']['after'][0]} on "
          f"{summary['host_load']['threads']} threads")


if __name__ == "__main__":
    main()
