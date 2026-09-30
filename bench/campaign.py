#!/usr/bin/env python3
"""A measurement campaign: every system, in blocks that take turns.

    python3 bench/campaign.py --out bench/results/r1/NAME --blocks 10 --trials 100

Runs on the host, in the repository root, with the machines of both test beds
up (the second one, vagrant/pqwireguard, is needed for pq-wireguard only; name
the systems with --systems to leave it out). The systems take turns block by
block, so that a change of the load on the host during
the campaign does not fall on one system alone. Writes env.json first and
report.md last. A campaign that was interrupted continues where it stopped.
"""

import argparse
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rig as rigmod  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT = ["wireguard", "wireguard-psk", "rosenpass", "pq-wireguard", "wgzk-zk", "wgzk-zkpq"]


def blocks_done(out, system):
    s = os.path.join(out, system, "summary.json")
    return len(json.load(open(s))["blocks"]) if os.path.exists(s) else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--blocks", type=int, default=10)
    ap.add_argument("--trials", type=int, default=100, help="trials per block")
    ap.add_argument("--idle", type=float, default=15)
    ap.add_argument("--settle", type=float, default=60)
    ap.add_argument("--systems", nargs="+", default=DEFAULT)
    ap.add_argument("--max-load", type=float, default=None,
                    help="do not start a block while the load of the host is above this")
    a = ap.parse_args()

    os.makedirs(a.out, exist_ok=True)
    env = os.path.join(a.out, "env.json")
    if not os.path.exists(env):
        subprocess.run([sys.executable, os.path.join(ROOT, "bench/env_dump.py"), env],
                       cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    for block in range(1, a.blocks + 1):
        for system in a.systems:
            if blocks_done(a.out, system) >= block:
                continue
            if a.max_load is not None:
                load = rigmod.Bed("pq" if system == "pq-wireguard" else "wgzk").host_load()["loadavg"][0]
                if load > a.max_load:
                    sys.exit(f"host load {load} is above {a.max_load}; block {block} of {system} "
                             "not started. Run the same command again to continue.")
            print(f"block {block}/{a.blocks}: {system}", flush=True)
            subprocess.run([sys.executable, os.path.join(ROOT, "bench/latency.py"), system,
                            "--trials", str(a.trials), "--idle", str(a.idle), "--settle", str(a.settle),
                            "--out", os.path.join(a.out, system), "--append"], cwd=ROOT, check=True)
    report = subprocess.run([sys.executable, os.path.join(ROOT, "bench/report.py"), a.out],
                            cwd=ROOT, check=True, capture_output=True, text=True).stdout
    with open(os.path.join(a.out, "report.md"), "w") as f:
        f.write(report)
    print(report)


if __name__ == "__main__":
    main()
