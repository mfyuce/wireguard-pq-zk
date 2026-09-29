# -*- mode: ruby -*-
# wgzk protocol R1: test bed of two virtual machines
#
# PRE-REQUISITE (once per machine):
#   1. Build on host:
#        bash vagrant/build-artifacts.sh      # kernel module, daemon, key generators
#   2. Build the base box (installs kernel 6.8.0-59-generic):
#        cd vagrant && bash build-base.sh
#
# USAGE:
#   vagrant up          # generates keys, spins up gateway + client, runs the end-to-end test
#   vagrant destroy -f  # tear everything down
#
# Environment (host), read at "vagrant up" and "vagrant provision":
#   WGZK_VARIANT    zk-pq (default) or zk-only
#   WGZK_EPOCH      credential epoch (default 1)
#   WGZK_VM_MEMORY  guest memory in MB (default 1024)
#   WGZK_VM_CPUS    guest CPUs (default 1)
#
# Network layout:
#   gateway  eth1=192.168.100.1  wg1r=fd57:475a:4b00::1/64, no peers at start
#   client   eth1=192.168.100.2  wg1l=address derived from the session key, /128
# The client has no long-term WireGuard key (docs/protocol-r1.md).

GATEWAY_IP = "192.168.100.1"
CLIENT_IP  = "192.168.100.2"
BASE_BOX   = "wgzk-base"

VARIANT   = ENV.fetch("WGZK_VARIANT", "zk-pq")
EPOCH     = ENV.fetch("WGZK_EPOCH", "1")
VM_MEMORY = ENV.fetch("WGZK_VM_MEMORY", "1024").to_i
VM_CPUS   = ENV.fetch("WGZK_VM_CPUS", "1").to_i

Vagrant.configure("2") do |config|
  config.vm.box = BASE_BOX
  config.vm.synced_folder ".", "/vagrant", type: "virtualbox"

  config.vm.provider "virtualbox" do |vb|
    vb.memory = VM_MEMORY
    vb.cpus   = VM_CPUS
    vb.customize ["modifyvm", :id, "--nicpromisc2", "allow-all"]
  end

  # Generate all keys on HOST before any VM boots
  config.trigger.before :up do |t|
    t.name = "Generate WireGuard + ZK keys"
    t.run  = { path: "vagrant/keygen.sh" }
  end

  # Both VMs: load wireguard.ko from host
  config.vm.provision "shell", path: "vagrant/02-load-module.sh"

  # ── GATEWAY ─────────────────────────────────────────────────────────────────
  config.vm.define "gateway", primary: true do |gw|
    gw.vm.hostname = "wgzk-gateway"
    gw.vm.network "private_network", ip: GATEWAY_IP,
                  virtualbox__intnet: "wgzk-internal"
    gw.vm.provision "shell", path: "vagrant/03-gateway.sh",
                    env: { "WGZK_VARIANT" => VARIANT, "WGZK_EPOCH" => EPOCH }
  end

  # ── CLIENT ───────────────────────────────────────────────────────────────────
  config.vm.define "client" do |cl|
    cl.vm.hostname = "wgzk-client"
    cl.vm.network "private_network", ip: CLIENT_IP,
                  virtualbox__intnet: "wgzk-internal"
    cl.vm.provision "shell", path: "vagrant/03-client.sh",
                    env: { "PEER_IP" => GATEWAY_IP,
                           "WGZK_VARIANT" => VARIANT, "WGZK_EPOCH" => EPOCH }
    cl.vm.provision "shell", path: "vagrant/04-test.sh"
  end
end
