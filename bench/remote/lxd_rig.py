#!/usr/bin/env python3
"""A test bed of virtual machines on hosts that are not ours, with LXD.

The machines are nested: the experimental kernel module is loaded inside
them and never into the kernel of a host. Everything this script creates on a
host has a name that starts with "wgzk", and "destroy" removes all of it and
compares the host with what "create" found.

    lxd_rig.py create  NAME --gateway-host USER@ADDR [--client-host USER@ADDR]
                            [--public-gateway ADDR] [--beds wgzk,pq] [--slot N]
    lxd_rig.py status  NAME
    lxd_rig.py destroy NAME

One host: gateway and client are neighbours on a bridge of their own
(addresses 192.168.100.1 and .2, as in the Vagrant test bed). Two hosts: the
client reaches the gateway over the network between the hosts, at
--public-gateway, and the host of the gateway forwards the ports.

Access. Nothing is left on a host that would let anybody in later, and no key
or password is put into a machine. A host is reached with the password of its
user, which sshpass takes from the environment variable SSHPASS; sudo on the
host gets its password, if it asks for one, from WGZK_RIG_SUDO_PASSWORD.
Neither is written anywhere. The machines are reached through their host
with "lxc exec". Their folder /vagrant is a directory of the host
(~/wgzk-rig/share) that this script fills from the repository.

Several test beds can share a host; each needs a --slot of its own (0 to 5),
which keeps their addresses apart. Pool, networks and profile are shared and
go when "destroy" is run for any of them, together with every machine whose
name starts with "wgzk", so destroy them all at the end and no earlier.

Result of "create": bench/rigs/NAME.json. Point WGZK_RIG at it and the harness
uses this test bed (it needs SSHPASS in its environment as well):

    WGZK_RIG=bench/rigs/NAME.json python3 bench/campaign.py --out ...
"""

import argparse
import json
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RIGS = os.path.join(ROOT, "bench", "rigs")
sys.path.insert(0, os.path.join(ROOT, "bench"))
import rig as rigmod  # noqa: E402

POOL = "wgzk"
NET_MGMT = "wgzkmgmt"
NET_TEST = "wgzktest"
PROFILE = "wgzk"
MGMT_NET = "192.168.251"
# UDP 51921 WireGuard, TCP 51821 side channel, UDP 9999 and 10000 Rosenpass and its WireGuard.
FORWARD = [("udp", 51921), ("tcp", 51821), ("udp", 9999), ("udp", 10000)]

BEDS = {
    "wgzk": {"image": "ubuntu:22.04", "kernel": "6.8.0-59-generic",
             "kernel_script": "/vagrant/vagrant/01-install-kernel.sh",
             "packages": ["wireguard-tools", "tcpdump", "iputils-ping"],
             "gateway": {"name": "wgzk-gateway", "mgmt": 11, "test": "192.168.100.1"},
             "client": {"name": "wgzk-client", "mgmt": 12, "test": "192.168.100.2"}},
    # The image of Ubuntu 18.04 comes without the agent that "lxc exec" talks to. The
    # machine installs it at its first boot from the share that LXD offers to every machine.
    "pq": {"image": "ubuntu:18.04", "kernel": "4.15.0-91-generic", "agent": "install",
           "kernel_script": "/vagrant/vagrant/pqwireguard/kernel.sh",
           "packages": ["tcpdump", "iputils-ping"],
           "gateway": {"name": "wgzk-pq-gateway", "mgmt": 21, "test": "192.168.101.1"},
           "client": {"name": "wgzk-pq-client", "mgmt": 22, "test": "192.168.101.2"}},
}

STATE_CMD = r"""
echo "pools $(lxc storage list -f csv </dev/null | cut -d, -f1 | sort | tr '\n' ' ')"
echo "networks $(lxc network list -f csv </dev/null | awk -F, '$3 == "YES" {print $1}' | sort | tr '\n' ' ')"
echo "profiles $(lxc profile list -f csv </dev/null | cut -d, -f1 | sort | tr '\n' ' ')"
echo "instances $(lxc list -f csv -c n </dev/null | sort | tr '\n' ' ')"
echo "images $(lxc image list -f csv -c f </dev/null | sort | tr '\n' ' ')"
echo "links $(ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -v -E '^(tap|veth|lxc|cilium)' | sort | tr '\n' ' ')"
echo "nft $(nft list tables 2>/dev/null | sort | tr '\n' ';')"
echo "forward $(iptables -S FORWARD 2>/dev/null | head -1)"
echo "workdir $(test -e ~/wgzk-rig && echo present || echo absent)"
"""


def die(msg):
    sys.exit("lxd_rig: " + msg)


def user_data(packages, install_agent=False):
    pk = "\n".join(f"  - {p}" for p in packages)
    agent = ""
    if install_agent:
        agent = ("  - mount -t 9p config /mnt -o access=0,trans=virtio\n"
                 "  - sh -c 'cd /mnt && ./install.sh'\n"
                 "  - umount /mnt\n"
                 "  - systemctl start --no-block lxd-agent\n")
    return f"""#cloud-config
package_update: true
packages:
{pk}
write_files:
  - path: /etc/systemd/journald.conf.d/wgzk.conf
    content: |
      [Journal]
      RateLimitIntervalSec=0
runcmd:
  - systemctl restart systemd-journald
{agent}"""


def network_config(mac_mgmt, mac_test, test_addr):
    return f"""version: 2
ethernets:
  mgmt0:
    match:
      macaddress: "{mac_mgmt}"
    set-name: mgmt0
    dhcp4: true
  wgtest0:
    match:
      macaddress: "{mac_test}"
    set-name: wgtest0
    addresses: [{test_addr}/24]
"""


def host_setup(host):
    home = host.run("echo $HOME").strip()
    host.run("mkdir -p ~/wgzk-rig/share ~/wgzk-rig/config")
    host.run(f"""
set -euo pipefail
lxc storage show {POOL} >/dev/null 2>&1 </dev/null || lxc storage create {POOL} dir </dev/null
lxc network show {NET_MGMT} >/dev/null 2>&1 </dev/null || lxc network create {NET_MGMT} \\
    ipv4.address={MGMT_NET}.1/24 ipv4.nat=true ipv4.dhcp=true ipv6.address=none </dev/null
lxc network show {NET_TEST} >/dev/null 2>&1 </dev/null || lxc network create {NET_TEST} \\
    ipv4.address=none ipv6.address=none </dev/null
if ! lxc profile show {PROFILE} >/dev/null 2>&1 </dev/null; then
    lxc profile create {PROFILE} </dev/null
    lxc profile set {PROFILE} limits.cpu=1 limits.memory=1GiB security.secureboot=false </dev/null
    lxc profile device add {PROFILE} root disk path=/ pool={POOL} size=8GiB </dev/null
    lxc profile device add {PROFILE} eth0 nic network={NET_MGMT} name=eth0 </dev/null
    lxc profile device add {PROFILE} eth1 nic network={NET_TEST} name=eth1 </dev/null
    lxc profile device add {PROFILE} share disk source={home}/wgzk-rig/share path=/vagrant </dev/null
fi
""", sudo=True)
    return home


def instance_create(host, home, bed, role, rig_name, slot):
    spec, inst = BEDS[bed], dict(BEDS[bed][role])
    inst["name"] = inst["name"].replace("wgzk-", f"wgzk-{rig_name}-", 1)
    n = inst["mgmt"] + 40 * slot
    mac_mgmt, mac_test = f"00:16:3e:77:00:{n:02x}", f"00:16:3e:77:01:{n:02x}"
    # The two cloud-init documents go to the host as files and from there into the
    # configuration of the machine.
    conf = f"{home}/wgzk-rig/config/{inst['name']}"
    no_agent = spec.get("agent") == "install"
    host.put_text(user_data(spec["packages"], no_agent), conf + ".user-data")
    host.put_text(network_config(mac_mgmt, mac_test, inst["test"]), conf + ".network-config")
    # Without the agent the two documents cannot reach the machine through it; they go on a disk.
    drive = f"lxc config device add {inst['name']} cidata disk source=cloud-init:config </dev/null\n" if no_agent else ""
    host.run(f"""
set -euo pipefail
if lxc info {inst['name']} >/dev/null 2>&1 </dev/null; then echo "exists: {inst['name']}"; exit 0; fi
lxc init {spec['image']} {inst['name']} --vm -p {PROFILE} </dev/null
lxc config device override {inst['name']} eth0 hwaddr={mac_mgmt} ipv4.address={MGMT_NET}.{n} </dev/null
lxc config device override {inst['name']} eth1 hwaddr={mac_test} </dev/null
lxc config set {inst['name']} user.user-data - < {conf}.user-data
lxc config set {inst['name']} user.network-config - < {conf}.network-config
{drive}lxc start {inst['name']} </dev/null
""", sudo=True, timeout=3600)
    return {"name": inst["name"], "mgmt": f"{MGMT_NET}.{n}", "test": inst["test"], "host": host.target,
            "bed": bed, "role": role}


def forward_ports(host, inst, listen):
    lines = "\n".join(
        f"lxc config device add {inst['name']} fw-{proto}-{port} proxy nat=true "
        f"listen={proto}:{listen}:{port} connect={proto}:{inst['mgmt']}:{port} </dev/null"
        for proto, port in FORWARD)
    host.run("set -euo pipefail\n" + lines + "\n", sudo=True)


def wait_for(host, name, what, test, timeout=1200):
    deadline = time.time() + timeout
    while time.time() < deadline:
        rc, out = host.guest(name, test, check=False, timeout=600)
        if rc == 0:
            return out
        time.sleep(5)
    die(f"{name}: {what} did not happen within {timeout} s")


def found_before(host):
    """How the host was found: by the first test bed that came to it, if one is there."""
    for name in sorted(os.listdir(RIGS)):
        if name.endswith(".json"):
            other = json.load(open(os.path.join(RIGS, name)))
            if host.target in other.get("hosts", {}):
                return other["hosts"][host.target]["before"]
    return host.state(STATE_CMD)


def bed_is_up(rig, bed, by_target):
    spec = BEDS[bed]
    for g in rig["guests"]:
        if g["bed"] != bed:
            continue
        rc, _ = by_target[g["host"]].guest(
            g["name"], f"test \"$(uname -r)\" = {spec['kernel']} && test -f /vagrant/vagrant/02-load-module.sh",
            check=False, timeout=60)
        if rc != 0:
            return False
    return bed in rig["beds"]


def create(a):
    """Makes a test bed, or adds to one: pairs of machines that are up are left alone, pairs
    that an earlier attempt left unfinished are removed and made again."""
    os.makedirs(RIGS, exist_ok=True)
    state_file = os.path.join(RIGS, a.name + ".json")
    known = os.path.join(RIGS, "known_hosts")
    gw_host = rigmod.Host(a.gateway_host, known)
    cl_host = rigmod.Host(a.client_host, known) if a.client_host and a.client_host != a.gateway_host else gw_host
    two = cl_host is not gw_host
    if two and not a.public_gateway:
        die("two hosts need --public-gateway, the address at which the client reaches the gateway's host")
    hosts = [gw_host] + ([cl_host] if two else [])
    by_target = {h.target: h for h in hosts}
    beds = a.beds.split(",")

    if os.path.exists(state_file):
        rig = json.load(open(state_file))
        if sorted(rig["hosts"]) != sorted(by_target):
            die(f"{state_file} describes a test bed on other hosts: {', '.join(rig['hosts'])}")
    else:
        rig = {"name": a.name, "kind": "remote", "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "known_hosts": known, "two_hosts": two,
               "hosts": {h.target: {"target": h.target, "before": found_before(h)} for h in hosts},
               "beds": {}, "guests": []}
        # The description exists from the first change on, so that destroy can always run.
        with open(state_file, "w") as f:
            json.dump(rig, f, indent=2)

    homes = {h.target: host_setup(h) for h in hosts}
    for h in hosts:
        h.push_share()
    for bed in beds:
        if bed_is_up(rig, bed, by_target):
            print(f"{bed}: the machines are up", flush=True)
            continue
        for g in [g for g in rig["guests"] if g["bed"] == bed]:
            by_target[g["host"]].run(f"lxc delete -f {g['name']} </dev/null", sudo=True, check=False)
        rig["guests"] = [g for g in rig["guests"] if g["bed"] != bed]
        gw = instance_create(gw_host, homes[gw_host.target], bed, "gateway", a.name, a.slot)
        cl = instance_create(cl_host, homes[cl_host.target], bed, "client", a.name, a.slot)
        rig["guests"] += [gw, cl]
        if two:
            listen = gw_host.run("ip -4 -o route get 1.1.1.1 | sed -n 's/.* src \\([0-9.]*\\).*/\\1/p'").strip()
            forward_ports(gw_host, gw, listen)
        rig["beds"][bed] = {"machines": {"gateway": gw["name"], "client": cl["name"]},
                            "hosts": {"gateway": gw_host.target, "client": cl_host.target},
                            "gw_ip": a.public_gateway if two else gw["test"],
                            "nic": "mgmt0" if two else "wgtest0",
                            "kernel": BEDS[bed]["kernel"]}
        with open(state_file, "w") as f:
            json.dump(rig, f, indent=2)

        spec = BEDS[bed]
        for g in (gw, cl):
            host = by_target[g["host"]]
            print(f"{g['name']} on {g['host']}: first boot", flush=True)
            wait_for(host, g["name"], "first boot",
                     "cloud-init status --wait >/dev/null 2>&1; test -f /vagrant/vagrant/02-load-module.sh")
            print(f"{g['name']}: kernel {spec['kernel']}", flush=True)
            host.guest(g["name"], f"bash {spec['kernel_script']}", timeout=3600)
            host.run(f"lxc restart {g['name']} </dev/null", sudo=True)
            wait_for(host, g["name"], "restart into the kernel",
                     f"test \"$(uname -r)\" = {spec['kernel']} && test -f /vagrant/vagrant/02-load-module.sh && "
                     "ip -4 -o addr show dev wgtest0 | grep -q inet")
    print(f"test bed {a.name} is up: WGZK_RIG={state_file}")
    return 0


def status(a):
    rig = json.load(open(os.path.join(RIGS, a.name + ".json")))
    hosts = {t: rigmod.Host(t, rig["known_hosts"]) for t in rig["hosts"]}
    for t, h in hosts.items():
        load = h.load()
        print(f"{t}: load {load['loadavg']}, {load['threads']} CPUs")
    for g in rig["guests"]:
        rc, out = hosts[g["host"]].guest(
            g["name"], "echo \"$(uname -r), load $(cut -d' ' -f1-3 /proc/loadavg), "
            "wireguard $(cat /sys/module/wireguard/srcversion 2>/dev/null || echo not loaded)\"",
            check=False, timeout=60)
        print(f"{g['name']:18} {g['host']:28} {out.strip() if rc == 0 else 'unreachable'}")
    return 0


def destroy(a):
    state_file = os.path.join(RIGS, a.name + ".json")
    rig = json.load(open(state_file))
    clean = True
    for target, h in rig["hosts"].items():
        host = rigmod.Host(target, rig["known_hosts"])
        before = h["before"]
        keep_images = " ".join(before.get("images", "").split())
        host.run(f"""
for i in $(lxc list -f csv -c n </dev/null | grep '^wgzk-' || true); do lxc delete -f "$i" </dev/null; done
lxc profile delete {PROFILE} 2>/dev/null </dev/null || true
lxc network delete {NET_TEST} 2>/dev/null </dev/null || true
lxc network delete {NET_MGMT} 2>/dev/null </dev/null || true
for f in $(lxc image list -f csv -c f </dev/null); do
    case " {keep_images} " in *" $f "*) ;; *) lxc image delete "$f" </dev/null ;; esac
done
lxc storage delete {POOL} 2>/dev/null </dev/null || true
rm -rf ~{target.split('@', 1)[0]}/wgzk-rig
""", sudo=True, check=False)
        # LXD leaves its table behind when its last network goes. It is removed if it
        # was not there before and holds no rule any more.
        if "table inet lxd" not in before.get("nft", ""):
            host.run("""
if nft list table inet lxd >/dev/null 2>&1 && ! nft list table inet lxd | grep -q -E 'jump|accept|drop|masquerade|dnat'; then
    nft delete table inet lxd
fi
""", sudo=True, check=False)
        after = host.state(STATE_CMD)
        same = True
        for k in sorted(before):
            if before[k] != after.get(k):
                same = False
                print(f"{target}: {k} differs\n   before: {before[k]}\n   after:  {after.get(k)}")
        print(f"{target}: " + ("as it was found" if same else "NOT as it was found, see above"))
        clean = clean and same
    os.rename(state_file, state_file + ".destroyed")
    return 0 if clean else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("action", choices=["create", "status", "destroy"])
    ap.add_argument("name")
    ap.add_argument("--gateway-host")
    ap.add_argument("--client-host")
    ap.add_argument("--public-gateway")
    ap.add_argument("--beds", default="wgzk")
    ap.add_argument("--slot", type=int, default=0, choices=range(6))
    a = ap.parse_args()
    if a.action == "create" and not a.gateway_host:
        die("create needs --gateway-host")
    return {"create": create, "status": status, "destroy": destroy}[a.action](a)


if __name__ == "__main__":
    sys.exit(main())
