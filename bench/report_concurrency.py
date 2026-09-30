#!/usr/bin/env python3
"""Markdown report over one bench/concurrency.py run.

    python3 bench/report_concurrency.py bench/results/r1/NAME > bench/results/r1/NAME/report.md
"""

import json
import os
import sys


def row(*cols):
    return "| " + " | ".join(str(c) for c in cols) + " |"


def main():
    if len(sys.argv) != 2:
        sys.exit(f"usage: {sys.argv[0]} RESULTS_DIR")
    outdir = sys.argv[1]
    summary = json.load(open(os.path.join(outdir, "summary.json")))

    print(f"# M-7 concurrency: n={summary['n']}, {summary['rounds']} round(s), "
          f"variant {summary['variant']}\n")
    print(f"{summary['succeeded']}/{summary['trials']} handshakes succeeded "
          f"({summary['failed']} failed) in {summary['seconds']}s. Host load "
          f"{summary['host_load']['before'][0]} to {summary['host_load']['after'][0]} on "
          f"{summary['host_load']['threads']} threads. Commit `{summary['commit'][:12]}`"
          + (f", {summary['dirty_files']} dirty file(s)" if summary["dirty_files"] else "") + ".\n")

    h = summary["handshake_ms"]
    if h.get("n"):
        print("## Handshake latency (first round trip minus steady median), ms\n")
        print(row("n", "min", "median", "mean", "max"))
        print(row("---", "---", "---", "---", "---"))
        print(row(h["n"], f"{h['min']:.2f}", f"{h['median']:.2f}", f"{h['mean']:.2f}", f"{h['max']:.2f}"))
        print()

    print("## Success by n\n")
    print(row("n", "trials", "succeeded"))
    print(row("---", "---", "---"))
    for n, d in sorted(summary["by_n"].items(), key=lambda kv: int(kv[0])):
        print(row(n, d["trials"], d["succeeded"]))
    print()

    print(f"Trials with exactly one client and one gateway [timing] line: "
          f"{summary['trials_with_exactly_one_handshake']} of {summary['succeeded']} "
          "succeeded (the phase breakdown below is over these only).\n")

    for side, label in (("client_ms", "Client phases"), ("gateway_ms", "Gateway phases")):
        phases = summary.get(side, {})
        if not any(v.get("n") for v in phases.values()):
            continue
        print(f"## {label}, ms\n")
        print(row("phase", "n", "median", "mean", "max"))
        print(row("---", "---", "---", "---", "---"))
        for phase, d in phases.items():
            if not d.get("n"):
                continue
            print(row(phase, d["n"], f"{d['median']:.3f}", f"{d['mean']:.3f}", f"{d['max']:.3f}"))
        print()


if __name__ == "__main__":
    main()
