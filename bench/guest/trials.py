#!/usr/bin/env python3
"""Handshake trials, run as root inside the client machine.

One JSON object per trial on standard output. A trial
  1. resets the initiator, so that the next packet needs a handshake
     (outside the measured interval),
  2. sends one echo request through the tunnel and takes the round-trip time
     that ping reports: the packet waits for the handshake, so this is the
     time from the first packet to its reply,
  3. sends further echo requests over the established session.

The handshake latency of a trial is the first round-trip time minus the median
of the later ones. Trials that get no reply are reported, not dropped.

Reset per system:
  wgzk         new session key and address (wg-zk-daemon new-connection)
  wgzk-rekey   same session key, the peer is removed and added again
  wireguard    the peer is removed and added again
  pqwireguard  the interface is removed and created again (pqwg-up)

Runs with Python 3.6, which is what Ubuntu 18.04 has.
"""

import argparse
import json
import re
import subprocess
import sys
import time

GW_ADDR = "fd57:475a:4b00::1"
TUNNEL_NET = "fd57:475a:4b00::/64"


def sh(cmd):
    return subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          universal_newlines=True)


def now_ns():
    return int(time.time() * 1e9)


def monotonic_us():
    return int(time.monotonic() * 1e6)


def must(cmd):
    r = sh(cmd)
    if r.returncode != 0:
        sys.exit(f"failed ({r.returncode}): {cmd}\n{r.stdout}{r.stderr}")
    return r.stdout


def ping(count, wait, interval=None):
    """Round-trip times in ms, in order; a lost packet is None."""
    opt = f"-i {interval} " if interval else ""
    r = sh(f"ping -6 -n {opt}-c {count} -W {wait} {GW_ADDR}")
    seen = {int(m.group(1)): float(m.group(2))
            for m in re.finditer(r"icmp_seq=(\d+) .*?time=([\d.]+) ms", r.stdout)}
    return [seen.get(i) for i in range(1, count + 1)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("system", choices=["wgzk", "wgzk-rekey", "wireguard", "pqwireguard"])
    ap.add_argument("--iface", required=True)
    ap.add_argument("--gw-pub", default="")
    ap.add_argument("--endpoint", default="")
    ap.add_argument("--psk-file", default="")
    ap.add_argument("--trials", type=int, default=100)
    ap.add_argument("--steady", type=int, default=5)
    ap.add_argument("--gap", type=float, default=0.3, help="pause between trials, seconds")
    ap.add_argument("--wait", type=int, default=5, help="seconds to wait for the first reply")
    ap.add_argument("--label", default="")
    a = ap.parse_args()

    psk = f" preshared-key {a.psk_file}" if a.psk_file else ""
    readd = (f"wg set {a.iface} peer {a.gw_pub} remove && "
             f"wg set {a.iface} peer {a.gw_pub} allowed-ips {TUNNEL_NET} endpoint {a.endpoint}{psk}")
    reset = {"wgzk": f"wg-zk-daemon new-connection --iface {a.iface}",
             "wgzk-rekey": readd,
             "wireguard": readd,
             "pqwireguard": "pqwg-up"}[a.system]
    if a.system != "pqwireguard" and not (a.gw_pub and a.endpoint):
        sys.exit("--gw-pub and --endpoint are required for this system")
    if a.system == "wgzk-rekey":
        must(f"wg-zk-daemon new-connection --iface {a.iface}")

    for i in range(1, a.trials + 1):
        start = now_ns()
        t = monotonic_us()
        must(reset)
        reset_us = monotonic_us() - t
        first = ping(1, a.wait)[0]
        steady = ping(a.steady, 2, 0.2) if first is not None else []
        print(json.dumps({
            "label": a.label, "system": a.system, "trial": i,
            "start_ns": start, "end_ns": now_ns(),
            "reset_us": reset_us, "ok": first is not None,
            "first_rtt_ms": first, "steady_rtt_ms": steady,
        }), flush=True)
        time.sleep(a.gap)


if __name__ == "__main__":
    main()
