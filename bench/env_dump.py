#!/usr/bin/env python3
"""Writes the facts about the test bed to a JSON file.

The paragraph of the paper that describes the test bed is written from this
file and from nothing else. Run on the host, in the repository root, with the
machines up:

    python3 bench/env_dump.py bench/results/env.json

The machines of the second test bed (vagrant/pqwireguard) are recorded if they
run, and left out if they do not.
"""

import datetime
import json
import os
import shlex
import subprocess
import sys
import tempfile

# Directory of the Vagrantfile, and its machines.
BEDS = {".": ("gateway", "client"), "vagrant/pqwireguard": ("pq-gateway", "pq-client")}

GUEST_FACTS = {
    "cpus": "nproc",
    "memory_kb": "awk '/MemTotal/ {print $2}' /proc/meminfo",
    "kernel": "uname -r",
    "os": "lsb_release -ds",
    "cpu_model": "awk -F': ' '/model name/ {print $2; exit}' /proc/cpuinfo",
    "hypervisor": "systemd-detect-virt || true",
    # What is loaded changes with the system under test; every block of a campaign records
    # it. Here: what is installed.
    "module_stock_srcversion": "modinfo -F srcversion /lib/modules/$(uname -r)/kernel/drivers/net/wireguard/wireguard.ko 2>/dev/null || true",
    "module_extra_srcversion": "modinfo -F srcversion /lib/modules/$(uname -r)/extra/wireguard.ko 2>/dev/null || true",
    "module_extra_version": "modinfo -F version /lib/modules/$(uname -r)/extra/wireguard.ko 2>/dev/null || true",
    "daemon_sha256": "sha256sum /usr/local/bin/wg-zk-daemon 2>/dev/null | cut -d' ' -f1",
    "rosenpass": "rosenpass --version 2>/dev/null || true",
    "wg_tools": "wg --version 2>/dev/null || true",
    "clocksource": "cat /sys/devices/system/clocksource/clocksource0/current_clocksource",
}

HOST_FACTS = {
    "cpu_model": "awk -F': ' '/model name/ {print $2; exit}' /proc/cpuinfo",
    "threads": "nproc",
    "memory_kb": "awk '/MemTotal/ {print $2}' /proc/meminfo",
    "kernel": "uname -r",
    "os": "lsb_release -ds",
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
    "module_sha256": "sha256sum vagrant/artifacts/wireguard.ko 2>/dev/null | cut -d' ' -f1",
    "daemon_sha256": "sha256sum vagrant/artifacts/wg-zk-daemon 2>/dev/null | cut -d' ' -f1",
    "artifacts_built_from": "sed -n '2p' vagrant/artifacts/MANIFEST 2>/dev/null",
    "rosenpass_archive_sha256": "sha256sum vagrant/artifacts/rosenpass-0.2.3/rosenpass-x86_64-linux-0.2.3.tar 2>/dev/null | cut -d' ' -f1",
    "pqwireguard_archive_sha256": "sha256sum vagrant/artifacts/pqwireguard-20200402.tar.bz2 2>/dev/null | cut -d' ' -f1",
}


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def sh(cmd):
    r = subprocess.run(["bash", "-c", cmd], cwd=ROOT, capture_output=True, text=True)
    return r.stdout.strip()


def number(text):
    return int(text) if text.isdigit() else text


def guests(bed, names):
    """The facts of the machines of one test bed; nothing if it is not up."""
    cfg = subprocess.run(["vagrant", "ssh-config"], cwd=os.path.join(ROOT, bed),
                         capture_output=True, text=True)
    if cfg.returncode != 0:
        return {}
    script = "; ".join(f"printf '%s\\t%s\\n' {k} \"$({v})\"" for k, v in GUEST_FACTS.items())
    out = {}
    with tempfile.NamedTemporaryFile("w", suffix=".cfg") as f:
        f.write(cfg.stdout + "\nHost *\n  LogLevel ERROR\n")
        f.flush()
        for name in names:
            r = subprocess.run(["ssh", "-F", f.name, name, "sudo bash -c " + shlex.quote(script)],
                               capture_output=True, text=True)
            if r.returncode != 0:
                continue
            facts = {}
            for line in r.stdout.splitlines():
                key, sep, value = line.partition("\t")
                if sep and key in GUEST_FACTS:
                    facts[key] = number(value.strip())
            out[name] = facts
    return out


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    env = {
        "recorded": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "host": {k: number(sh(v)) for k, v in HOST_FACTS.items()},
        "code": {k: number(sh(v)) for k, v in CODE_FACTS.items()},
        "guests": {},
    }
    for bed, names in BEDS.items():
        env["guests"].update(guests(bed, names))
    if "gateway" not in env["guests"] or "client" not in env["guests"]:
        sys.exit("the machines gateway and client do not answer; are they up?")
    os.makedirs(os.path.dirname(os.path.abspath(sys.argv[1])), exist_ok=True)
    with open(sys.argv[1], "w") as f:
        json.dump(env, f, indent=2, sort_keys=True)
        f.write("\n")
    print(json.dumps(env, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
