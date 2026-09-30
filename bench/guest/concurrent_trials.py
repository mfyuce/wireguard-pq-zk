#!/usr/bin/env python3
"""M-7 concurrency trials, run as root inside the client machine.

N interfaces (wgc0..wgc(N-1), provisioned by vagrant/03-client-m7.sh) are given a fresh
session key and address each round (wg-zk-daemon new-connection), then all N send one echo
request at the same moment (bound to their own interface, so the per-interface routing table
that provisioning set up picks the right one), then a few steady ones each. One JSON object
per (round, interface) on standard output; see bench/guest/trials.py for the single-interface
version this borrows its reset/ping/steady structure from.
"""

import argparse
import json
import re
import subprocess
import sys
import time

GW_ADDR = "fd57:475a:4b00::1"


def sh(cmd):
    return subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          universal_newlines=True)


def must(cmd):
    r = sh(cmd)
    if r.returncode != 0:
        sys.exit(f"failed ({r.returncode}): {cmd}\n{r.stdout}{r.stderr}")
    return r.stdout


def now_ns():
    return int(time.time() * 1e9)


def monotonic_us():
    return int(time.monotonic() * 1e6)


def new_connection(iface):
    must(f"wg-zk-daemon new-connection --iface {iface}")


def ping_popen(iface, count, wait, interval=None):
    """Starts one ping bound to `iface`; read its result with ping_result()."""
    opt = f"-i {interval} " if interval else ""
    return subprocess.Popen(f"ping -6 -n {opt}-I {iface} -c {count} -W {wait} {GW_ADDR}",
                            shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True)


def ping_result(p, count):
    """Round-trip times in ms, in order; a lost packet is None."""
    out, _ = p.communicate()
    seen = {int(m.group(1)): float(m.group(2))
            for m in re.finditer(r"icmp_seq=(\d+) .*?time=([\d.]+) ms", out)}
    return [seen.get(i) for i in range(1, count + 1)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, required=True, help="number of concurrent interfaces")
    ap.add_argument("--rounds", type=int, default=1)
    ap.add_argument("--steady", type=int, default=5)
    ap.add_argument("--gap", type=float, default=0.3, help="pause between rounds, seconds")
    ap.add_argument("--wait", type=int, default=5, help="seconds to wait for the first reply")
    ap.add_argument("--label", default="")
    a = ap.parse_args()

    ifaces = [f"wgc{k}" for k in range(a.n)]

    for r in range(1, a.rounds + 1):
        start = now_ns()
        t0 = monotonic_us()
        for iface in ifaces:
            new_connection(iface)
        reset_us = monotonic_us() - t0

        # All N interfaces' first ping starts within one Popen loop, not one at a time
        # with a wait in between: this is the "at the same moment" requirement.
        first_procs = [ping_popen(iface, 1, a.wait) for iface in ifaces]
        firsts = [ping_result(p, 1)[0] for p in first_procs]

        steady_procs = [ping_popen(iface, a.steady, 2, 0.2) if first is not None else None
                        for iface, first in zip(ifaces, firsts)]
        steadies = [ping_result(p, a.steady) if p is not None else []
                   for p in steady_procs]

        end = now_ns()
        for iface, first, steady in zip(ifaces, firsts, steadies):
            print(json.dumps({
                "label": a.label, "system": "wgzk-m7", "round": r, "iface": iface, "n": a.n,
                "start_ns": start, "end_ns": end, "reset_us": reset_us,
                "ok": first is not None, "first_rtt_ms": first, "steady_rtt_ms": steady,
            }), flush=True)
        time.sleep(a.gap)


if __name__ == "__main__":
    main()
