#!/usr/bin/env python3
"""Rosenpass trials, run as root inside the client machine (measurement M-3).

Rosenpass exchanges keys on its own schedule and hands each key to WireGuard
as a preshared key. A trial measures the two parts of a cold start apart:

  exchange_ms   from the start of the Rosenpass process to the moment the
                preshared key is installed in the WireGuard peer of the client
  first_rtt_ms  the first packet through the tunnel after that, which waits for
                an ordinary WireGuard handshake with the preshared key in place

Interface, address and keys exist before the process starts. Between the two
parts the trial pauses, so that the gateway has installed its key as well; the
pause is not counted. One JSON object per trial on standard output.
"""

import argparse
import json
import os
import re
import select
import subprocess
import sys
import time

DEV = "rosenpass0"
GW_ADDR = "fd57:475a:4b00::1"
CL_ADDR = "fd57:475a:4b00::2"
TUNNEL_NET = "fd57:475a:4b00::/64"
SECRET = "/etc/rosenpass/client.secret"
PUBLIC = "/vagrant/vagrant/keys/rosenpass"


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


def must(cmd):
    r = sh(cmd)
    if r.returncode != 0:
        sys.exit(f"failed ({r.returncode}): {cmd}\n{r.stdout}{r.stderr}")
    return r.stdout


def ping(count, wait, interval=None):
    opt = f"-i {interval} " if interval else ""
    r = sh(f"ping -6 -n {opt}-c {count} -W {wait} {GW_ADDR}")
    seen = {int(m.group(1)): float(m.group(2))
            for m in re.finditer(r"icmp_seq=(\d+) .*?time=([\d.]+) ms", r.stdout)}
    return [seen.get(i) for i in range(1, count + 1)]


def psk_installed(gw_wgpk):
    out = sh(f"wg show {DEV} preshared-keys").stdout
    return any(line.split()[:1] == [gw_wgpk] and line.split()[1:] != ["(none)"]
               for line in out.splitlines() if line.strip())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gateway", required=True, help="address of the gateway on the test network")
    ap.add_argument("--port", type=int, default=9999, help="Rosenpass port; WireGuard uses the next one")
    ap.add_argument("--trials", type=int, default=100)
    ap.add_argument("--steady", type=int, default=5)
    ap.add_argument("--gap", type=float, default=0.3)
    ap.add_argument("--pause", type=float, default=0.05)
    ap.add_argument("--timeout", type=float, default=10)
    a = ap.parse_args()

    gw_wgpk = open(f"{PUBLIC}/gateway.public/wgpk").read().strip()
    exchange = ["rosenpass", "exchange",
                "secret-key", f"{SECRET}/pqsk", "public-key", f"{SECRET}/pqpk",
                "peer", "public-key", f"{PUBLIC}/gateway.public/pqpk",
                "endpoint", f"{a.gateway}:{a.port}",
                "wireguard", DEV, gw_wgpk,
                "endpoint", f"{a.gateway}:{a.port + 1}", "allowed-ips", TUNNEL_NET]

    for i in range(1, a.trials + 1):
        sh("pkill -x rosenpass")
        sh(f"ip link del {DEV}")
        must(f"ip link add dev {DEV} type wireguard && wg set {DEV} private-key {SECRET}/wgsk && "
             f"ip link set {DEV} mtu 1380 && ip -6 addr add {CL_ADDR}/128 dev {DEV} && "
             f"ip link set {DEV} up && ip -6 route replace {TUNNEL_NET} dev {DEV}")

        start = time.time_ns()
        t0 = time.monotonic_ns()
        p = subprocess.Popen(exchange, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        os.set_blocking(p.stdout.fileno(), False)
        announced = installed = None
        deadline = time.monotonic() + a.timeout
        buf = b""
        while installed is None and time.monotonic() < deadline:
            if announced is None:
                if select.select([p.stdout], [], [], 0.001)[0]:
                    buf += p.stdout.read() or b""
                    if b"exchanged" in buf:
                        announced = time.monotonic_ns()
            if psk_installed(gw_wgpk):
                installed = time.monotonic_ns()
        first, steady = None, []
        if installed is not None:
            time.sleep(a.pause)
            first = ping(1, 5)[0]
            if first is not None:
                steady = ping(a.steady, 2, 0.2)
        p.terminate()
        try:
            p.wait(timeout=2)
        except subprocess.TimeoutExpired:
            p.kill()
        print(json.dumps({
            "system": "rosenpass", "trial": i, "start_ns": start, "end_ns": time.time_ns(),
            "ok": first is not None,
            "exchange_ms": None if installed is None else (installed - t0) / 1e6,
            "announced_ms": None if announced is None else (announced - t0) / 1e6,
            "first_rtt_ms": first, "steady_rtt_ms": steady,
        }), flush=True)
        time.sleep(a.gap)
    sh("pkill -x rosenpass")
    sh(f"ip link del {DEV}")


if __name__ == "__main__":
    main()
