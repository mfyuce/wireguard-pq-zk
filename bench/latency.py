#!/usr/bin/env python3
"""Handshake latency of one system on the test bed (measurement M-1).

Runs on the host, in the repository root, with both machines up:

    python3 bench/latency.py SYSTEM --trials 1000 --out bench/results/r1/NAME

Systems:
    wireguard         WireGuard as shipped with the kernel, long-term keys
    wireguard-psk     the same with a preshared key on both sides
    wgzk-zk           this design, authorization only, new connection per trial
    wgzk-zkpq         this design with ML-KEM, new connection per trial
    wgzk-zk-rekey     as wgzk-zk, but every trial is a handshake inside one connection
    wgzk-zkpq-rekey   as wgzk-zkpq, likewise
    rosenpass         Rosenpass (official release) on WireGuard as shipped; every trial is a
                      cold start: its key exchange, then the WireGuard handshake

Metric, the same for every system: the round-trip time of the first packet on
a tunnel without a session, minus the median round-trip time of the packets
that follow over the established session. Identity and interface are
configured before the first packet is sent. See bench/guest/trials.py.

Rosenpass exchanges keys on its own schedule, so its trials report two parts:
the duration of its exchange (process start to preshared key installed) and
the WireGuard handshake that follows with the key in place, measured as above.
See bench/guest/rosenpass_trials.py.

CPU time (measurement M-2) is taken over the same trials, in two ways.
Daemon: the time that the threads of the daemon spent on a CPU, from
/proc/<pid>/task/*/schedstat, divided by the number of successful handshakes;
precise, and defined for this design only. Machine: the busy time of the whole
machine from /proc/stat over the trials, minus the busy time of an idle window
scaled to the same length; an upper bound, since it contains the driver of the
trials, and the same procedure for every system and for both machines.

Output directory: trials.jsonl (one record per trial; for wgzk with the timing
lines of both daemons), summary.json, setup.log.
"""

import argparse
import json
import os
import shlex
import statistics
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GW_IP = "192.168.100.1"
GW_PORT = 51921

SYSTEMS = {
    "wireguard":       {"kind": "wireguard", "iface": "wg0", "psk": False},
    "wireguard-psk":   {"kind": "wireguard", "iface": "wg0", "psk": True},
    "wgzk-zk":         {"kind": "wgzk", "iface": "wg1l", "variant": "zk-only"},
    "wgzk-zkpq":       {"kind": "wgzk", "iface": "wg1l", "variant": "zk-pq"},
    "wgzk-zk-rekey":   {"kind": "wgzk-rekey", "iface": "wg1l", "variant": "zk-only"},
    "wgzk-zkpq-rekey": {"kind": "wgzk-rekey", "iface": "wg1l", "variant": "zk-pq"},
    "rosenpass":       {"kind": "rosenpass", "iface": "rosenpass0"},
}


class Rig:
    def __init__(self, outdir):
        self.sshcfg = os.path.join(outdir, "ssh.cfg")
        cfg = subprocess.run(["vagrant", "ssh-config"], cwd=ROOT, capture_output=True, text=True)
        if cfg.returncode != 0:
            sys.exit("vagrant ssh-config failed; are both machines up?\n" + cfg.stderr)
        with open(self.sshcfg, "w") as f:
            f.write(cfg.stdout + "\nHost *\n  LogLevel ERROR\n")
        self.log = open(os.path.join(outdir, "setup.log"), "w")

    def ssh(self, vm, script):
        return ["ssh", "-F", self.sshcfg, vm, "sudo bash -c " + shlex.quote(script)]

    def must(self, vm, script, timeout=300):
        r = subprocess.run(self.ssh(vm, script), capture_output=True, text=True, timeout=timeout)
        self.log.write(f"\n$ [{vm}] {script}\n{r.stdout}{r.stderr}[exit {r.returncode}]\n")
        self.log.flush()
        if r.returncode != 0:
            sys.exit(f"step failed in {vm} (exit {r.returncode}): {script}\n{r.stdout}{r.stderr}")
        return r.stdout

    def cursor(self, vm):
        out = self.must(vm, "journalctl -u wgzk -n 1 --show-cursor -o cat --no-pager | tail -1")
        return out.split("cursor: ", 1)[1].strip() if "cursor: " in out else ""

    def timing(self, vm, cursor):
        """[timing] lines since `cursor`, with the time the journal received them."""
        after = f"--after-cursor={shlex.quote(cursor)}" if cursor else ""
        out = self.must(vm, f"journalctl -u wgzk -o json --no-pager {after} | grep -F '[timing]' || true")
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


DAEMONS = {"wgzk": "wg-zk-daemon", "wgzk-rekey": "wg-zk-daemon", "rosenpass": "rosenpass"}


def cpu_snapshot(rig, vm, process):
    """Busy time of the machine and on-CPU time of `process`, both in seconds."""
    script = "head -1 /proc/stat; getconf CLK_TCK; date +%s.%N"
    if process:
        script += (f"; for p in $(pidof {process}); do for f in /proc/$p/task/*/schedstat; "
                   "do cat $f; done; done 2>/dev/null")
    lines = rig.must(vm, script).splitlines()
    f = [int(x) for x in lines[0].split()[1:]]
    hz = int(lines[1])
    # user nice system idle iowait irq softirq steal
    busy = (f[0] + f[1] + f[2] + f[5] + f[6] + f[7]) / hz
    daemon = sum(int(ln.split()[0]) for ln in lines[3:] if ln.split()) / 1e9 if process else None
    return {"busy_s": busy, "daemon_s": daemon, "clock_s": float(lines[2])}


def cpu_report(idle0, idle1, run0, run1, handshakes):
    """CPU time per handshake of one machine, in ms."""
    idle_rate = (idle1["busy_s"] - idle0["busy_s"]) / (idle1["clock_s"] - idle0["clock_s"])
    seconds = run1["clock_s"] - run0["clock_s"]
    busy = run1["busy_s"] - run0["busy_s"]
    out = {"window_s": round(seconds, 1), "busy_s": round(busy, 3),
           "idle_busy_per_s": round(idle_rate, 5),
           "machine_ms_per_handshake": None, "daemon_ms_per_handshake": None}
    if handshakes:
        out["machine_ms_per_handshake"] = (busy - idle_rate * seconds) * 1000 / handshakes
        if run0["daemon_s"] is not None and run1["daemon_s"] is not None:
            out["daemon_ms_per_handshake"] = (run1["daemon_s"] - run0["daemon_s"]) * 1000 / handshakes
    return out


def setup(rig, name, spec):
    tools = ("mkdir -p /etc/systemd/journald.conf.d; "
             "printf '[Journal]\\nRateLimitIntervalSec=0\\n' > /etc/systemd/journald.conf.d/wgzk.conf; "
             "systemctl restart systemd-journald; ")
    if spec["kind"] == "rosenpass":
        rig.must("gateway", tools + "bash /vagrant/vagrant/11-rosenpass.sh gateway keys")
        rig.must("client", tools + "bash /vagrant/vagrant/11-rosenpass.sh client keys")
        rig.must("gateway", "bash /vagrant/vagrant/11-rosenpass.sh gateway start")
        rig.must("client", "bash /vagrant/vagrant/11-rosenpass.sh client prepare")
    elif spec["kind"] == "wireguard":
        psk = "psk" if spec["psk"] else ""
        rig.must("gateway", tools + f"bash /vagrant/vagrant/10-stock.sh gateway {psk}")
        rig.must("client", tools + f"bash /vagrant/vagrant/10-stock.sh client {psk}")
    else:
        v = spec["variant"]
        rig.must("gateway", tools + "bash /vagrant/vagrant/02-load-module.sh && "
                 f"WGZK_VARIANT={v} bash /vagrant/vagrant/03-gateway.sh")
        rig.must("client", tools + "rm -rf /etc/systemd/system/wgzk.service.d /etc/wgzk-test.env; "
                 "bash /vagrant/vagrant/02-load-module.sh && "
                 f"PEER_IP={GW_IP} WGZK_VARIANT={v} bash /vagrant/vagrant/03-client.sh")
    # What is loaded, as the machines see it.
    facts = {}
    for vm in ("gateway", "client"):
        facts[vm] = {
            "module_srcversion": rig.must(vm, "cat /sys/module/wireguard/srcversion").strip(),
            "daemon_sha256": rig.must(vm, "sha256sum /usr/local/bin/wg-zk-daemon | cut -d' ' -f1").strip(),
        }
        if spec["kind"] == "rosenpass":
            facts[vm]["rosenpass"] = rig.must(vm, "rosenpass --version").strip()
            facts[vm]["rosenpass_sha256"] = rig.must(
                vm, "sha256sum /usr/local/bin/rosenpass | cut -d' ' -f1").strip()
    return facts


def quantile(sorted_values, q):
    """Linear interpolation between the closest ranks."""
    if not sorted_values:
        return None
    pos = (len(sorted_values) - 1) * q
    lo = int(pos)
    hi = min(lo + 1, len(sorted_values) - 1)
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (pos - lo)


def describe(values):
    v = sorted(values)
    if not v:
        return {"n": 0}
    return {"n": len(v), "min": v[0], "p25": quantile(v, 0.25), "median": quantile(v, 0.5),
            "p75": quantile(v, 0.75), "p95": quantile(v, 0.95), "p99": quantile(v, 0.99),
            "max": v[-1], "mean": statistics.fmean(v)}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("system", choices=sorted(SYSTEMS))
    ap.add_argument("--trials", type=int, default=100)
    ap.add_argument("--steady", type=int, default=5)
    ap.add_argument("--gap", type=float, default=0.3)
    ap.add_argument("--idle", type=float, default=30, help="seconds of the idle window for the CPU time")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    spec = SYSTEMS[a.system]
    os.makedirs(a.out, exist_ok=True)
    rig = Rig(a.out)
    facts = setup(rig, a.system, spec)
    gw_pub = open(os.path.join(ROOT, "vagrant/keys/public_right")).read().strip()
    wgzk = spec["kind"] in ("wgzk", "wgzk-rekey")
    cursors = {vm: rig.cursor(vm) for vm in ("gateway", "client")} if wgzk else {}

    # Traffic before the trials, so that no trial pays for cold caches or for
    # address resolution on the test network.
    rig.must("client", f"ping -n -c 3 -W 2 {GW_IP} >/dev/null; "
             "ping -6 -n -c 3 -W 5 fd57:475a:4b00::1 >/dev/null || true")
    time.sleep(1)
    if wgzk:
        cursors = {vm: rig.cursor(vm) for vm in ("gateway", "client")}

    # The client of Rosenpass is a new process in every trial; only the gateway has a
    # process whose time can be followed.
    process = {"gateway": DAEMONS.get(spec["kind"]),
               "client": None if spec["kind"] == "rosenpass" else DAEMONS.get(spec["kind"])}
    idle0 = {vm: cpu_snapshot(rig, vm, process[vm]) for vm in process}
    time.sleep(a.idle)
    idle1 = {vm: cpu_snapshot(rig, vm, process[vm]) for vm in process}
    run0 = idle1

    if spec["kind"] == "rosenpass":
        cmd = (f"python3 /vagrant/bench/guest/rosenpass_trials.py --gateway {GW_IP} "
               f"--trials {a.trials} --steady {a.steady} --gap {a.gap}")
    else:
        psk = "--psk-file /vagrant/vagrant/keys/stock.psk" if spec.get("psk") else ""
        cmd = (f"python3 /vagrant/bench/guest/trials.py {spec['kind']} --iface {spec['iface']} "
               f"--gw-pub {gw_pub} --endpoint {GW_IP}:{GW_PORT} {psk} --trials {a.trials} "
               f"--steady {a.steady} --gap {a.gap} --label {a.system}")
    started = time.time()
    trials = []
    with subprocess.Popen(rig.ssh("client", cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as p:
        for line in p.stdout:
            if line.startswith("{"):
                trials.append(json.loads(line))
                if len(trials) % 50 == 0:
                    print(f"  {len(trials)}/{a.trials} trials", flush=True)
        err = p.stderr.read()
    if p.returncode != 0:
        sys.exit(f"the trial loop failed (exit {p.returncode}):\n{err}")
    run1 = {vm: cpu_snapshot(rig, vm, process[vm]) for vm in process}

    if wgzk:
        time.sleep(1)
        client = rig.timing("client", cursors["client"])
        gateway = {}
        for ln in rig.timing("gateway", cursors["gateway"]):
            gateway.setdefault(ln.get("nonce_prefix"), []).append(ln)
        for t in trials:
            lo, hi = t["start_ns"] // 1000, t["end_ns"] // 1000
            t["client"] = [ln for ln in client if lo <= ln["journal_us"] <= hi]
            t["gateway"] = [g for ln in t["client"] for g in gateway.get(ln.get("nonce_prefix"), [])]

    for t in trials:
        steady = [x for x in t["steady_rtt_ms"] if x is not None]
        t["steady_median_ms"] = statistics.median(steady) if steady else None
        t["handshake_ms"] = (t["first_rtt_ms"] - t["steady_median_ms"]
                             if t["ok"] and steady else None)
    with open(os.path.join(a.out, "trials.jsonl"), "w") as f:
        for t in trials:
            f.write(json.dumps(t, sort_keys=True) + "\n")

    ok = [t for t in trials if t["handshake_ms"] is not None]
    summary = {
        "system": a.system,
        "trials": len(trials),
        "succeeded": len(ok),
        "failed": len(trials) - len(ok),
        "seconds": round(time.time() - started, 1),
        "handshake_ms": describe([t["handshake_ms"] for t in ok]),
        "first_rtt_ms": describe([t["first_rtt_ms"] for t in ok]),
        "steady_rtt_ms": describe([t["steady_median_ms"] for t in ok]),
        "reset_ms": describe([t["reset_us"] / 1000 for t in trials if "reset_us" in t]),
        "machines": facts,
        "cpu": {vm: cpu_report(idle0[vm], idle1[vm], run0[vm], run1[vm], len(ok)) for vm in process},
        "commit": subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                                 text=True).stdout.strip(),
        "dirty_files": len(subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True,
                                          text=True).stdout.splitlines()),
    }
    if spec["kind"] == "rosenpass":
        summary["exchange_ms"] = describe([t["exchange_ms"] for t in ok])
        summary["cold_start_ms"] = describe([t["exchange_ms"] + t["handshake_ms"] for t in ok])
    if wgzk:
        one = [t for t in ok if len(t["client"]) == 1 and len(t["gateway"]) == 1]
        summary["trials_with_exactly_one_handshake"] = len(one)
        for side, keys in (("client", ("zk_us", "encap_us", "tls_us", "write_us", "psk_us", "tail_us", "total_us")),
                           ("gateway", ("wait_ct_us", "verify_us", "decap_us", "peer_us", "total_us"))):
            summary[side + "_ms"] = {k[:-3]: describe([int(t[side][0][k]) / 1000 for t in one]) for k in keys}
    with open(os.path.join(a.out, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2, sort_keys=True)
        f.write("\n")
    rig.log.close()
    os.remove(rig.sshcfg)

    h = summary["handshake_ms"]
    print(f"{a.system}: {summary['succeeded']}/{summary['trials']} handshakes; latency median "
          f"{h.get('median', float('nan')):.2f} ms, quartiles {h.get('p25', float('nan')):.2f} to "
          f"{h.get('p75', float('nan')):.2f}, p95 {h.get('p95', float('nan')):.2f}, "
          f"p99 {h.get('p99', float('nan')):.2f}; steady round trip median "
          f"{summary['steady_rtt_ms'].get('median', float('nan')):.2f} ms")


if __name__ == "__main__":
    main()
