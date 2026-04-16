#!/usr/bin/env python3
"""Compute latency stats from run-trials.sh JSON output (µs granularity)."""
import json
import statistics
import sys


def stats(xs):
    if not xs:
        return None
    xs = sorted(xs)
    return {
        "n": len(xs),
        "median": statistics.median(xs),
        "mean": statistics.mean(xs),
        "stdev": statistics.pstdev(xs) if len(xs) > 1 else 0.0,
        "p95": xs[int(0.95 * (len(xs) - 1))] if len(xs) >= 20 else None,
        "p99": xs[int(0.99 * (len(xs) - 1))] if len(xs) >= 100 else None,
        "min": xs[0],
        "max": xs[-1],
    }


def fmt(s, unit_divisor=1000.0, unit="ms"):
    if s is None:
        return "no data"
    parts = [f"n={s['n']}",
             f"median={s['median']/unit_divisor:.3f}{unit}",
             f"mean={s['mean']/unit_divisor:.3f}{unit}",
             f"stdev={s['stdev']/unit_divisor:.3f}{unit}"]
    if s["p95"] is not None:
        parts.append(f"p95={s['p95']/unit_divisor:.3f}{unit}")
    if s["p99"] is not None:
        parts.append(f"p99={s['p99']/unit_divisor:.3f}{unit}")
    parts.append(f"min={s['min']/unit_divisor:.3f}{unit}")
    parts.append(f"max={s['max']/unit_divisor:.3f}{unit}")
    return " ".join(parts)


def main():
    variant, path = sys.argv[1], sys.argv[2]
    rows = []
    cpu = None
    with open(path) as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            obj = json.loads(ln)
            if "cpu_summary" in obj:
                cpu = obj["cpu_summary"]
            else:
                rows.append(obj)
    if not rows:
        print(f"variant={variant}: no trials")
        return
    total = [r["total_us"] for r in rows]
    zk = [r["zk_us"] for r in rows]
    mlkem = [r["mlkem_us"] for r in rows]
    psk = [r["psk_us"] for r in rows]
    tail = [r["tail_us"] for r in rows]
    encap = [r.get("encap_us", 0) for r in rows]
    tls = [r.get("tls_us", 0) for r in rows]
    write = [r.get("write_us", 0) for r in rows]
    warm_total = [r["total_us"] - r.get("tls_us", 0) for r in rows]

    print(f"variant={variant} n_trials={len(rows)}")
    print(f"  total (need→set):     {fmt(stats(total))}")
    print(f"  zk (proof gen):       {fmt(stats(zk))}")
    print(f"  mlkem (encap + TLS):  {fmt(stats(mlkem))}")
    if any(tls):
        print(f"    encap (ML-KEM enc): {fmt(stats(encap))}")
        print(f"    tls (TCP+TLS setup):{fmt(stats(tls))}")
        print(f"    write (msg send):   {fmt(stats(write))}")
        print(f"  warm-equiv (total - tls): {fmt(stats(warm_total))}")
    print(f"  psk (wg set inject):  {fmt(stats(psk))}")
    print(f"  tail (genl SET_PROOF):{fmt(stats(tail))}")
    if cpu:
        per = cpu["task_ms"] / cpu["n"] if cpu["n"] else 0
        print(f"  cpu: n={cpu['n']} total_task_clock_ms={cpu['task_ms']:.2f} "
              f"ctx_switches={cpu['context_switches']} per_handshake_ms={per:.3f}")


if __name__ == "__main__":
    main()
