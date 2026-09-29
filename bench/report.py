#!/usr/bin/env python3
"""Tables of a measurement campaign, from the summaries that bench/latency.py wrote.

    python3 bench/report.py bench/results/r1 [--max-load 4]

With --max-load, the trials of every block during which the load of the host
was above the limit (before or after the block) are left out, and the report
says how many blocks that were. CPU times are then taken from the remaining
blocks as well.

Prints Markdown: handshake latency of every system, the phases of this design
on both sides, CPU time. Every number is computed from trials.jsonl again and
compared with the summary, so that a table cannot drift from its data.
"""

import json
import os
import statistics
import sys

ORDER = ["wireguard", "wireguard-psk", "rosenpass", "pq-wireguard", "wgzk-zk", "wgzk-zkpq",
         "wgzk-zk-rekey", "wgzk-zkpq-rekey"]


def quantile(v, q):
    v = sorted(v)
    pos = (len(v) - 1) * q
    lo = int(pos)
    hi = min(lo + 1, len(v) - 1)
    return v[lo] + (v[hi] - v[lo]) * (pos - lo)


def fmt(x, digits=2):
    return "" if x is None else f"{x:.{digits}f}"


def row(name, values):
    if not values:
        return f"| {name} | 0 | | | | | | |"
    q = [quantile(values, p) for p in (0.25, 0.5, 0.75, 0.95, 0.99)]
    return (f"| {name} | {len(values)} | {fmt(q[1])} | {fmt(q[0])} | {fmt(q[2])} | "
            f"{fmt(q[3])} | {fmt(q[4])} | {fmt(max(values))} |")


def block_load(b):
    return max(b["host"]["loadavg_before"][0], b["host"]["loadavg_after"][0])


def cpu_of(blocks, vm):
    """CPU time per handshake over the given blocks, as bench/latency.py computes it."""
    handshakes = sum(b["succeeded"] for b in blocks)
    out = {"window_s": round(sum(b["cpu"][vm]["window_s"] for b in blocks), 1), "handshakes": handshakes}
    for key, name in (("busy_s", "machine"), ("irq_ticks_s", "interrupt_ticks"), ("daemon_s", "daemon")):
        if not handshakes or any(key not in b["cpu"][vm]["used"] for b in blocks):
            out[name + "_ms_per_handshake"] = None
            continue
        used = sum(b["cpu"][vm]["used"][key] for b in blocks)
        idle = sum(b["cpu"][vm]["idle_per_s"][key] * b["cpu"][vm]["window_s"] for b in blocks)
        out[name + "_ms_per_handshake"] = (used - idle) * 1000 / handshakes
    return out


def main():
    args = sys.argv[1:]
    limit = None
    if "--max-load" in args:
        i = args.index("--max-load")
        limit = float(args[i + 1])
        del args[i:i + 2]
    if len(args) != 1:
        sys.exit(__doc__)
    root = args[0]
    runs = {}
    left_out = {}
    for name in sorted(os.listdir(root)):
        s = os.path.join(root, name, "summary.json")
        t = os.path.join(root, name, "trials.jsonl")
        if not (os.path.isfile(s) and os.path.isfile(t)):
            continue
        summary = json.load(open(s))
        trials = [json.loads(line) for line in open(t)]
        if limit is not None:
            keep = [b for b in summary["blocks"] if block_load(b) <= limit]
            left_out[name] = len(summary["blocks"]) - len(keep)
            kept = {b["block"] for b in keep}
            trials = [x for x in trials if x["block"] in kept]
            ok = [x for x in trials if x.get("handshake_ms") is not None]
            summary["blocks"] = keep
            summary["trials"], summary["succeeded"] = len(trials), len(ok)
            summary["failed"] = len(trials) - len(ok)
            summary["handshake_ms"] = {"median": statistics.median([x["handshake_ms"] for x in ok])} if ok else {}
            loads = [block_load(b) for b in keep] + [min(b["host"]["loadavg_before"][0],
                                                          b["host"]["loadavg_after"][0]) for b in keep]
            summary["host_load"] = {"min": min(loads) if loads else None, "max": max(loads) if loads else None,
                                    "threads": summary["host_load"]["threads"]}
            summary["cpu"] = {vm: cpu_of(keep, vm) for vm in summary["cpu"]} if keep else {}
        runs[name] = (summary, trials)
    if not runs:
        sys.exit(f"no summaries under {root}")
    if limit is not None:
        print(f"Blocks with a host load above {limit} are left out: "
              + ", ".join(f"{n} {k}" for n, k in left_out.items()) + ".\n")
    names = sorted(runs, key=lambda n: (ORDER.index(runs[n][0]["system"])
                                        if runs[n][0]["system"] in ORDER else 99, n))

    head = "| {} | n | median | p25 | p75 | p95 | p99 | max |\n|---|---|---|---|---|---|---|---|"
    print("## Handshake latency (ms): first packet to its reply, minus the steady round trip\n")
    print("| run | system | blocks | trials | succeeded | failed | host load, lowest to highest | threads |\n"
          "|---|---|---|---|---|---|---|---|")
    for n in names:
        s = runs[n][0]
        h = s["host_load"]
        # What ran, not what the repository looked like: module and daemon of every block.
        under_test = {json.dumps(b["machines"], sort_keys=True) for b in s["blocks"]}
        print(f"| {n} | {s['system']} | {len(s['blocks'])} | {s['trials']} | {s['succeeded']} | "
              f"{s['failed']} | {h['min']} to {h['max']} | {h['threads']} |")
        if len(under_test) > 1:
            sys.exit(f"{n}: its blocks ran different modules or daemons")
    print("\n" + head.format("run"))
    for n in names:
        s, trials = runs[n]
        values = [t["handshake_ms"] for t in trials if t.get("handshake_ms") is not None]
        print(row(n, values))
        check = s["handshake_ms"].get("median")
        if values and check is not None and abs(statistics.median(values) - check) > 1e-9:
            sys.exit(f"{n}: summary and trials disagree on the median")

    print("\n## Steady round trip over the established session (ms)\n\n" + head.format("run"))
    for n in names:
        print(row(n, [t["steady_median_ms"] for t in runs[n][1] if t.get("steady_median_ms") is not None]))

    ros = [n for n in names if runs[n][0]["system"] == "rosenpass"]
    if ros:
        print("\n## Rosenpass: key exchange and cold start (ms)\n\n" + head.format("run, part"))
        for n in ros:
            ok = [t for t in runs[n][1] if t.get("handshake_ms") is not None]
            print(row(f"{n}, exchange", [t["exchange_ms"] for t in ok]))
            print(row(f"{n}, exchange + handshake", [t["exchange_ms"] + t["handshake_ms"] for t in ok]))

    ours = [n for n in names if runs[n][0]["system"].startswith("wgzk")]
    if ours:
        print("\n## This design: phases inside the daemons (ms), trials with exactly one handshake\n")
        for n in ours:
            one = [t for t in runs[n][1] if t.get("handshake_ms") is not None
                   and len(t.get("client", [])) == 1 and len(t.get("gateway", [])) == 1]
            print(f"\n### {n} ({len(one)} trials)\n\n" + head.format("side, phase"))
            for side, keys in (("client", ("zk_us", "encap_us", "tls_us", "write_us", "psk_us", "total_us")),
                               ("gateway", ("wait_ct_us", "verify_us", "decap_us", "peer_us", "total_us"))):
                for k in keys:
                    print(row(f"{side}, {k[:-3]}", [int(t[side][0][k]) / 1000 for t in one]))
            print(row("outside the daemons",
                      [t["handshake_ms"] - (int(t["client"][0]["total_us"]) + int(t["gateway"][0]["total_us"])) / 1000
                       for t in one]))

    print("\n## CPU time per handshake (ms)\n")
    print("Daemon: on-CPU time of its threads. All tasks: on-CPU time of every task of the machine,\n"
          "idle window subtracted; it contains the driver of the trials. Interrupts: tick counts of\n"
          "10 ms, idle window subtracted.\n")
    print("| run | machine | handshakes | daemon | all tasks | interrupts (ticks) | window (s) |\n"
          "|---|---|---|---|---|---|---|")
    for n in names:
        for vm, c in sorted(runs[n][0].get("cpu", {}).items()):
            print(f"| {n} | {vm} | {c['handshakes']} | {fmt(c.get('daemon_ms_per_handshake'), 3)} | "
                  f"{fmt(c.get('machine_ms_per_handshake'), 3)} | "
                  f"{fmt(c.get('interrupt_ticks_ms_per_handshake'), 3)} | {c['window_s']} |")


if __name__ == "__main__":
    main()
