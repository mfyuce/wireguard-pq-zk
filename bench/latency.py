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
    pq-wireguard      PQ-WireGuard, the artefact of its authors, on its own test bed
                      (vagrant/pqwireguard: Ubuntu 18.04, kernel 4.15.0-91); both machines of
                      that test bed must be up

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
precise, and defined for this design only. Machine: the time that all tasks of
the machine, kernel threads included, spent on a CPU over the trials
(/proc/schedstat), minus that of an idle window scaled to the same length; an
upper bound, since it contains the driver of the trials, and the same
procedure for every system and for both machines. Interrupt work that runs
while the CPU is otherwise idle is not in it; /proc/stat counts it, in ticks
of 10 ms, and is recorded next to it.

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
    "pq-wireguard":    {"kind": "pqwireguard", "iface": "wg0", "vagrant": "vagrant/pqwireguard",
                        "machines": {"gateway": "pq-gateway", "client": "pq-client"},
                        "gw_ip": "192.168.101.1"},
}


class Rig:
    def __init__(self, outdir, spec):
        self.sshcfg = os.path.join(outdir, "ssh.cfg")
        self.names = spec.get("machines", {})
        cfg = subprocess.run(["vagrant", "ssh-config"], cwd=os.path.join(ROOT, spec.get("vagrant", ".")),
                             capture_output=True, text=True)
        if cfg.returncode != 0:
            sys.exit("vagrant ssh-config failed; are both machines up?\n" + cfg.stderr)
        with open(self.sshcfg, "w") as f:
            f.write(cfg.stdout + "\nHost *\n  LogLevel ERROR\n")
        self.log = open(os.path.join(outdir, "setup.log"), "a")

    def ssh(self, vm, script):
        return ["ssh", "-F", self.sshcfg, self.names.get(vm, vm), "sudo bash -c " + shlex.quote(script)]

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
    """On-CPU time of all tasks, of `process`, and the tick counts, all in seconds."""
    script = ("head -1 /proc/stat; getconf CLK_TCK; date +%s.%N; "
              "awk '/^cpu/ {s += $8} END {print s}' /proc/schedstat")
    if process:
        script += (f"; for p in $(pidof {process}); do for f in /proc/$p/task/*/schedstat; "
                   "do cat $f; done; done 2>/dev/null")
    lines = rig.must(vm, script).splitlines()
    f = [int(x) for x in lines[0].split()[1:]]
    hz = int(lines[1])
    # user nice system idle iowait irq softirq steal
    ticks = (f[0] + f[1] + f[2] + f[5] + f[6] + f[7]) / hz
    daemon = sum(int(ln.split()[0]) for ln in lines[4:] if ln.split()) / 1e9 if process else None
    return {"busy_s": int(lines[3]) / 1e9, "ticks_s": ticks, "irq_ticks_s": (f[5] + f[6]) / hz,
            "daemon_s": daemon, "clock_s": float(lines[2])}


def cpu_block(idle0, idle1, run0, run1):
    """What one block of trials used, and what the idle window before it used per second."""
    idle_seconds = idle1["clock_s"] - idle0["clock_s"]
    out = {"window_s": run1["clock_s"] - run0["clock_s"], "used": {}, "idle_per_s": {}}
    for key in ("busy_s", "ticks_s", "irq_ticks_s", "daemon_s"):
        if run0[key] is None or run1[key] is None:
            continue
        out["used"][key] = run1[key] - run0[key]
        out["idle_per_s"][key] = (idle1[key] - idle0[key]) / idle_seconds
    return out


def cpu_report(blocks, vm):
    """CPU time per handshake of one machine over all blocks, in ms."""
    handshakes = sum(b["succeeded"] for b in blocks)
    out = {"window_s": round(sum(b["cpu"][vm]["window_s"] for b in blocks), 1), "handshakes": handshakes}
    names = {"busy_s": "machine", "ticks_s": "machine_ticks", "irq_ticks_s": "interrupt_ticks",
             "daemon_s": "daemon"}
    for key, name in names.items():
        if not handshakes or any(key not in b["cpu"][vm]["used"] for b in blocks):
            out[name + "_ms_per_handshake"] = None
            continue
        used = sum(b["cpu"][vm]["used"][key] for b in blocks)
        idle = sum(b["cpu"][vm]["idle_per_s"][key] * b["cpu"][vm]["window_s"] for b in blocks)
        out[name + "_ms_per_handshake"] = (used - idle) * 1000 / handshakes
        out[name + "_idle_share"] = idle / used if used else None
    return out


def setup(rig, name, spec):
    tools = ("mkdir -p /etc/systemd/journald.conf.d; "
             "printf '[Journal]\\nRateLimitIntervalSec=0\\n' > /etc/systemd/journald.conf.d/wgzk.conf; "
             "systemctl restart systemd-journald; ")
    if spec["kind"] == "pqwireguard":
        # The gateway learns the key of the client from the shared folder.
        gw = spec["gw_ip"]
        rig.must("client", tools + f"bash /vagrant/vagrant/pqwireguard/provision.sh client {gw}")
        rig.must("gateway", tools + f"bash /vagrant/vagrant/pqwireguard/provision.sh gateway {gw}")
    elif spec["kind"] == "rosenpass":
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
            "kernel": rig.must(vm, "uname -r").strip(),
            "module_srcversion": rig.must(vm, "cat /sys/module/wireguard/srcversion").strip(),
            "module_version": rig.must(vm, "cat /sys/module/wireguard/version 2>/dev/null || true").strip(),
            "daemon_sha256": rig.must(vm, "sha256sum /usr/local/bin/wg-zk-daemon 2>/dev/null | cut -d' ' -f1").strip(),
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
    ap.add_argument("--append", action="store_true",
                    help="add the trials as a further block to those that the directory holds")
    a = ap.parse_args()

    spec = SYSTEMS[a.system]
    os.makedirs(a.out, exist_ok=True)
    trials_file = os.path.join(a.out, "trials.jsonl")
    summary_file = os.path.join(a.out, "summary.json")
    earlier, blocks = [], []
    if os.path.exists(trials_file):
        if not a.append:
            sys.exit(f"{a.out} holds trials already; use --append or another directory")
        earlier = [json.loads(line) for line in open(trials_file)]
        blocks = json.load(open(summary_file))["blocks"]
        if json.load(open(summary_file))["system"] != a.system:
            sys.exit(f"{a.out} holds trials of another system")
    # Other work on the host delays the machines. The load is recorded with every run.
    load_before = open("/proc/loadavg").read().split()[:3]
    rig = Rig(a.out, spec)
    facts = setup(rig, a.system, spec)
    gw_pub = open(os.path.join(ROOT, "vagrant/keys/public_right")).read().strip()
    gw_ip = spec.get("gw_ip", GW_IP)
    wgzk = spec["kind"] in ("wgzk", "wgzk-rekey")
    cursors = {vm: rig.cursor(vm) for vm in ("gateway", "client")} if wgzk else {}

    # Traffic before the trials, so that no trial pays for cold caches or for
    # address resolution on the test network.
    rig.must("client", f"ping -n -c 3 -W 2 {gw_ip} >/dev/null; "
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
    elif spec["kind"] == "pqwireguard":
        cmd = (f"python3 /vagrant/bench/guest/trials.py pqwireguard --iface {spec['iface']} "
               f"--trials {a.trials} --steady {a.steady} --gap {a.gap} --label {a.system}")
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
    block = {
        "block": len(blocks) + 1,
        "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
        "seconds": round(time.time() - started, 1),
        "trials": len(trials),
        "succeeded": sum(t["handshake_ms"] is not None for t in trials),
        "machines": facts,
        "host": {"threads": os.cpu_count(),
                 "loadavg_before": [float(x) for x in load_before],
                 "loadavg_after": [float(x) for x in open("/proc/loadavg").read().split()[:3]]},
        "cpu": {vm: cpu_block(idle0[vm], idle1[vm], run0[vm], run1[vm]) for vm in process},
        "commit": subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                                 text=True).stdout.strip(),
        "dirty_files": len(subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True,
                                          text=True).stdout.splitlines()),
    }
    for t in trials:
        t["block"] = block["block"]
        t["trial"] += len(earlier)
    blocks.append(block)
    trials = earlier + trials
    with open(trials_file, "w") as f:
        for t in trials:
            f.write(json.dumps(t, sort_keys=True) + "\n")

    ok = [t for t in trials if t["handshake_ms"] is not None]
    summary = {
        "system": a.system,
        "trials": len(trials),
        "succeeded": len(ok),
        "failed": len(trials) - len(ok),
        "blocks": blocks,
        "handshake_ms": describe([t["handshake_ms"] for t in ok]),
        "first_rtt_ms": describe([t["first_rtt_ms"] for t in ok]),
        "steady_rtt_ms": describe([t["steady_median_ms"] for t in ok]),
        "reset_ms": describe([t["reset_us"] / 1000 for t in trials if "reset_us" in t]),
        "host_load": {"min": min(min(b["host"]["loadavg_before"][0], b["host"]["loadavg_after"][0])
                                 for b in blocks),
                      "max": max(max(b["host"]["loadavg_before"][0], b["host"]["loadavg_after"][0])
                                 for b in blocks),
                      "threads": os.cpu_count()},
        "cpu": {vm: cpu_report(blocks, vm) for vm in process},
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
    with open(summary_file, "w") as f:
        json.dump(summary, f, indent=2, sort_keys=True)
        f.write("\n")
    rig.log.close()
    os.remove(rig.sshcfg)

    h = summary["handshake_ms"]
    print(f"{a.system}: {summary['succeeded']}/{summary['trials']} handshakes; latency median "
          f"{h.get('median', float('nan')):.2f} ms, quartiles {h.get('p25', float('nan')):.2f} to "
          f"{h.get('p75', float('nan')):.2f}, p95 {h.get('p95', float('nan')):.2f}, "
          f"p99 {h.get('p99', float('nan')):.2f}; steady round trip median "
          f"{summary['steady_rtt_ms'].get('median', float('nan')):.2f} ms; {len(blocks)} block(s); "
          f"host load {summary['host_load']['min']} to {summary['host_load']['max']} on "
          f"{summary['host_load']['threads']} threads")


if __name__ == "__main__":
    main()
