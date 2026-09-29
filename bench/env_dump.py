#!/usr/bin/env python3
"""Writes the facts about the test bed to a JSON file.

The paragraph of the paper that describes the test bed is written from this
file and from nothing else. Run on the host, in the repository root, with both
machines up:

    python3 bench/env_dump.py bench/results/env.json
"""

import datetime
import json
import os
import subprocess
import sys

GUESTS = ("gateway", "client")

GUEST_FACTS = {
    "cpus": "nproc",
    "memory_kb": "awk '/MemTotal/ {print $2}' /proc/meminfo",
    "kernel": "uname -r",
    "os": ". /etc/os-release && echo \"$PRETTY_NAME\"",
    "cpu_model": "awk -F': ' '/model name/ {print $2; exit}' /proc/cpuinfo",
    "hypervisor": "systemd-detect-virt || true",
    "wireguard_module_srcversion": "cat /sys/module/wireguard/srcversion 2>/dev/null || true",
    "wireguard_module_path": "modinfo -n wireguard 2>/dev/null || true",
    "daemon_sha256": "sha256sum /usr/local/bin/wg-zk-daemon 2>/dev/null | cut -d' ' -f1",
    "wg_tools": "wg --version 2>/dev/null || true",
    "clocksource": "cat /sys/devices/system/clocksource/clocksource0/current_clocksource",
}

HOST_FACTS = {
    "cpu_model": "awk -F': ' '/model name/ {print $2; exit}' /proc/cpuinfo",
    "threads": "nproc",
    "memory_kb": "awk '/MemTotal/ {print $2}' /proc/meminfo",
    "kernel": "uname -r",
    "os": ". /etc/os-release && echo \"$PRETTY_NAME\"",
    "virtualbox": "VBoxManage --version",
    "vagrant": "vagrant --version",
    "rustc": "rustc --version 2>/dev/null || true",
    "gcc": "gcc --version | head -1",
    "governor": "cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || true",
}

CODE_FACTS = {
    "commit": "git rev-parse HEAD",
    "branch": "git rev-parse --abbrev-ref HEAD",
    "dirty_files": "git status --porcelain | wc -l",
    "module_sha256": "sha256sum wireguard-6.8/wireguard.ko 2>/dev/null | cut -d' ' -f1",
    "daemon_sha256": "sha256sum userspace/wg-zk-daemon/target/release/wg-zk-daemon 2>/dev/null | cut -d' ' -f1",
}


def sh(cmd):
    r = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
    return r.stdout.strip()


def number(text):
    return int(text) if text.isdigit() else text


def guest(name):
    # One ssh session per guest: the facts come back as name<TAB>value lines.
    script = "; ".join(f"printf '%s\\t%s\\n' {k} \"$({v})\"" for k, v in GUEST_FACTS.items())
    r = subprocess.run(["vagrant", "ssh", name, "-c", f"sudo bash -c {json.dumps(script)}"],
                       capture_output=True, text=True)
    facts = {}
    for line in r.stdout.splitlines():
        key, sep, value = line.partition("\t")
        if sep and key in GUEST_FACTS:
            facts[key] = number(value.strip())
    missing = sorted(set(GUEST_FACTS) - set(facts))
    if missing:
        facts["missing"] = missing
    return facts


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    env = {
        "recorded": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "host": {k: number(sh(v)) for k, v in HOST_FACTS.items()},
        "code": {k: number(sh(v)) for k, v in CODE_FACTS.items()},
        "guests": {name: guest(name) for name in GUESTS},
    }
    os.makedirs(os.path.dirname(os.path.abspath(sys.argv[1])), exist_ok=True)
    with open(sys.argv[1], "w") as f:
        json.dump(env, f, indent=2, sort_keys=True)
        f.write("\n")
    print(json.dumps(env, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
