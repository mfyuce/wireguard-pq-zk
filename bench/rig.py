"""How the harness reaches the machines of a test bed.

Two kinds of test bed exist.

vagrant  The machines of the repository (Vagrantfile, vagrant/pqwireguard) on
         this host. /vagrant is a folder that both machines share with the
         host. This is the default.

remote   Machines that bench/remote/lxd_rig.py created on another host. They
         are reached through that host with "lxc exec"; /vagrant is a
         directory of the host that the machines see and that push_share()
         fills from the repository. The host is reached with the password of
         its user (sshpass takes it from the environment variable SSHPASS);
         nothing that gives access is stored on the host or in a machine.

The environment variable WGZK_RIG names the description of a remote test bed
(a JSON file written by lxd_rig.py). Without it the Vagrant test bed is used.
"""

import json
import os
import shlex
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

VAGRANT = {
    "name": "vagrant",
    "kind": "vagrant",
    "beds": {
        "wgzk": {"vagrant": ".", "machines": {"gateway": "gateway", "client": "client"},
                 "gw_ip": "192.168.100.1", "nic": "enp0s8"},
        "pq": {"vagrant": "vagrant/pqwireguard",
               "machines": {"gateway": "pq-gateway", "client": "pq-client"},
               "gw_ip": "192.168.101.1", "nic": "enp0s8"},
    },
}

# What the machines need under /vagrant, relative to the repository root.
SHARE = ["vagrant/01-install-kernel.sh", "vagrant/02-load-module.sh", "vagrant/03-gateway.sh",
         "vagrant/03-client.sh", "vagrant/04-test.sh", "vagrant/10-stock.sh", "vagrant/11-rosenpass.sh",
         "vagrant/pqwireguard/", "vagrant/artifacts/", "vagrant/keys/", "bench/guest/",
         "bench/acceptance/wgzk_probe.py"]

# A script reaches a machine on standard input. It is stored there first and
# run with an empty standard input, so that no command inside can eat the rest of it.
IN_GUEST = ("bash -c 'f=$(mktemp /run/wgzk-cmd.XXXXXX) && cat > \"$f\" && bash \"$f\" </dev/null; "
            "rc=$?; rm -f \"$f\"; exit $rc'")


def description():
    path = os.environ.get("WGZK_RIG")
    if not path:
        return VAGRANT
    with open(path) as f:
        rig = json.load(f)
    rig["path"] = os.path.abspath(path)
    return rig


class Host:
    """A host under the machines of a remote test bed."""

    def __init__(self, target, known_hosts):
        if "SSHPASS" not in os.environ:
            sys.exit("SSHPASS is not set: the password of the user on the host of the test bed")
        self.target = target
        self.user, self.addr = target.split("@", 1)
        self.opts = ["-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
                     "-o", f"UserKnownHostsFile={known_hosts}", "-o", "StrictHostKeyChecking=accept-new",
                     "-o", "ConnectTimeout=10", "-o", "LogLevel=ERROR", "-o", "ServerAliveInterval=30"]
        self._asks = None

    def ssh(self, remote):
        return ["sshpass", "-e", "ssh", *self.opts, self.target, remote]

    def sudo(self):
        """The sudo command of this host and what it wants on its standard input first."""
        if self._asks is None:
            self._asks = subprocess.run(self.ssh("sudo -n true"), capture_output=True).returncode != 0
        if not self._asks:
            return "sudo", ""
        password = os.environ.get("WGZK_RIG_SUDO_PASSWORD")
        if password is None:
            sys.exit("WGZK_RIG_SUDO_PASSWORD is not set, and sudo on the host asks for a password")
        # -k: the password is asked for every time, so that the first line of the
        # input is always read by sudo and never taken for a line of a script.
        return "sudo -k -S -p ''", password + "\n"

    def run(self, script, sudo=False, check=True, timeout=1800):
        """Runs `script` on the host. Commands in it that read their standard input
        need a redirection of their own."""
        prefix, first = self.sudo() if sudo else ("", "")
        r = subprocess.run(self.ssh(f"{prefix} bash -s".strip()), input=first + script,
                           capture_output=True, text=True, timeout=timeout)
        if check and r.returncode != 0:
            sys.exit(f"on {self.target} (exit {r.returncode}):\n{script.strip()[:600]}\n--\n{r.stdout}{r.stderr}")
        return r.stdout

    def guest_command(self, name):
        prefix, first = self.sudo()
        return self.ssh(f"{prefix} lxc exec {shlex.quote(name)} -- {IN_GUEST}"), first

    def guest(self, name, script, check=True, timeout=1800):
        cmd, first = self.guest_command(name)
        try:
            r = subprocess.run(cmd, input=first + script, capture_output=True, text=True, timeout=timeout)
            rc, out = r.returncode, r.stdout + r.stderr
        except subprocess.TimeoutExpired as e:
            out = e.stdout.decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
            rc, out = 124, out + "\n[timeout]"
        if check and rc != 0:
            sys.exit(f"in {name} on {self.target} (exit {rc}):\n{script.strip()[:600]}\n--\n{out}")
        return rc, out

    def put_text(self, text, path):
        r = subprocess.run(self.ssh(f"cat > {shlex.quote(path)}"), input=text, capture_output=True, text=True)
        if r.returncode != 0:
            sys.exit(f"cannot write {path} on {self.target}: {r.stderr}")

    def state(self, command):
        out = self.run(command, sudo=True)
        return {line.split(" ", 1)[0]: line.split(" ", 1)[1].strip() if " " in line else ""
                for line in out.splitlines() if line.strip()}

    def rsync(self, args):
        r = subprocess.run(["rsync", "-e", "sshpass -e ssh " + " ".join(shlex.quote(o) for o in self.opts),
                            *args], cwd=ROOT, capture_output=True, text=True)
        if r.returncode != 0:
            sys.exit("rsync failed: " + " ".join(args) + "\n" + r.stdout + r.stderr)

    def push_share(self):
        """Fills ~/wgzk-rig/share, which the machines see as /vagrant, from the repository.
        What the machines wrote there as root is given to the user first, keys stay."""
        self.run(f"chown -R {self.user}: ~{self.user}/wgzk-rig/share", sudo=True)
        present = [p for p in SHARE if os.path.exists(os.path.join(ROOT, p.rstrip("/")))]
        self.rsync(["-aR", "--exclude", "__pycache__", "--exclude", "*.tar", "--exclude", "*.tar.bz2",
                    *present, f"{self.target}:wgzk-rig/share/"])

    def load(self):
        out = self.run("cat /proc/loadavg; nproc").split()
        return {"host": self.addr, "threads": int(out[-1]), "loadavg": [float(x) for x in out[:3]]}


class Bed:
    """One pair of machines, gateway and client."""

    def __init__(self, bed="wgzk", workdir=None):
        self.rig = description()
        if bed not in self.rig["beds"]:
            sys.exit(f"the test bed {self.rig['name']} has no machines for '{bed}'")
        self.bed = self.rig["beds"][bed]
        self.names = self.bed["machines"]
        self.gw_ip = self.bed["gw_ip"]
        self.nic = self.bed["nic"]
        self.remote = self.rig["kind"] != "vagrant"
        self._tmp = None
        if self.remote:
            self.hosts = {t: Host(t, self.rig["known_hosts"]) for t in self.rig["hosts"]}
            self.host_of = {vm: self.hosts[t] for vm, t in self.bed["hosts"].items()}
            return
        cfg = subprocess.run(["vagrant", "ssh-config"], cwd=os.path.join(ROOT, self.bed["vagrant"]),
                             capture_output=True, text=True)
        if cfg.returncode != 0:
            sys.exit("vagrant ssh-config failed; are the machines up?\n" + cfg.stderr)
        if workdir:
            self.sshcfg = os.path.join(workdir, "ssh.cfg")
            out = open(self.sshcfg, "w")
        else:
            out = self._tmp = tempfile.NamedTemporaryFile("w", suffix=".cfg")
            self.sshcfg = out.name
        out.write(cfg.stdout + "\nHost *\n  LogLevel ERROR\n")
        out.flush()

    def close(self):
        if self._tmp:
            self._tmp.close()
        elif not self.remote and os.path.exists(self.sshcfg):
            os.remove(self.sshcfg)

    # ── commands in a machine, as root ───────────────────────────────────────
    def command(self, vm):
        """Argument vector and first input of a command that takes a script on its
        standard input and runs it as root in `vm`."""
        if self.remote:
            return self.host_of[vm].guest_command(self.names[vm])
        return ["ssh", "-F", self.sshcfg, self.names.get(vm, vm), "sudo " + IN_GUEST], ""

    def run(self, vm, script, timeout=300):
        """Returns exit status, standard output and standard error."""
        cmd, first = self.command(vm)
        try:
            r = subprocess.run(cmd, input=first + script, capture_output=True, text=True, timeout=timeout)
            return r.returncode, r.stdout, r.stderr
        except subprocess.TimeoutExpired as e:
            out = e.stdout.decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
            return 124, out, "[timeout]"

    def popen(self, vm, script):
        """Starts `script` in `vm`; its output can be read while it runs."""
        cmd, first = self.command(vm)
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True)
        p.stdin.write(first + script)
        p.stdin.close()
        return p

    # ── the host or hosts under the machines ─────────────────────────────────
    def host_load(self):
        """Load and size of the host under the machines; of the busier one if there are two."""
        if not self.remote:
            return {"host": "local", "threads": os.cpu_count(),
                    "loadavg": [float(x) for x in open("/proc/loadavg").read().split()[:3]]}
        loads = [h.load() for h in self.hosts.values()]
        return max(loads, key=lambda x: x["loadavg"][0] / x["threads"])

    # ── /vagrant ─────────────────────────────────────────────────────────────
    def push_share(self):
        if self.remote:
            for h in self.hosts.values():
                h.push_share()

    def sync_keys(self):
        """What one machine put under /vagrant/vagrant/keys reaches the other one. Only
        machines on two hosts need it; on one host, and with Vagrant, they share the folder."""
        if not self.remote or len(self.hosts) < 2:
            return
        with tempfile.TemporaryDirectory() as d:
            for h in self.hosts.values():
                h.run(f"chown -R {h.user}: ~{h.user}/wgzk-rig/share", sudo=True)
                h.rsync(["-a", f"{h.target}:wgzk-rig/share/vagrant/keys/", d + "/"])
            for h in self.hosts.values():
                h.rsync(["-a", d + "/", f"{h.target}:wgzk-rig/share/vagrant/keys/"])
