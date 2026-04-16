#!/bin/bash
# Host-side orchestrator for the N-concurrent scalability benchmark.
#
# Flow:
#   1. Mark journald cursor on BOTH VMs.
#   2. Invoke scale-run.sh inside the client VM (it fires N parallel handshakes).
#   3. Pull [timing] lines emitted since the cursors from BOTH VMs' wgzk daemon,
#      tagged with side=client|gateway.
#   4. Merge into a single JSONL; emit a scale_summary with wall time and counts.
#
# Usage (host, after `scale-setup.sh N`): bash bench/scale-driver.sh N [OUT]
#
# The gateway-side [timing] lines answer the scalability question (server
# per-handshake cost under concurrent load). Client-side lines are kept so
# the paper can report both halves of the handshake under contention.
set -euo pipefail

N="${1:-64}"
OUT="${2:-bench/results/scale-$N.jsonl}"
mkdir -p "$(dirname "$OUT")"
: >"$OUT"

t_start_ns=$(date +%s%N)
# Use epoch seconds — 1 s rewind to tolerate clock skew between host and VMs.
SINCE_EPOCH=$(( t_start_ns / 1000000000 - 1 ))

# Fire the concurrent trigger inside the client VM. scale-run.sh does its own
# journalctl capture too but we ignore its output here — we want host-side
# merged capture with wall time measured from the host's perspective.
vagrant ssh client -c "sudo bash /vagrant/bench/scale-run.sh $N /tmp/scale-$N-inner.jsonl >/dev/null" 2>&1 | tail -3

t_end_ns=$(date +%s%N)
wall_us=$(( (t_end_ns - t_start_ns) / 1000 ))

# Give daemons a moment so stragglers reach the journal.
sleep 0.5

# Pull [timing] lines from both VMs, decorate with side tag, merge.
extract() {
    local SIDE="$1"
    local VM="$2"
    local SINCE="$3"
    vagrant ssh "$VM" -c "sudo journalctl -u wgzk --since '@$SINCE' -o cat" 2>/dev/null | \
        awk -v SIDE="$SIDE" '
        /\[timing\]/ {
          token=""; total=""; zk=""; mlkem=""; psk=""; tail=""; encap=""; tls=""; write=""
          for (i=1; i<=NF; i++) {
            split($i, kv, "=")
            if (kv[1]=="token")    token=kv[2]
            if (kv[1]=="total_us") total=kv[2]
            if (kv[1]=="zk_us")    zk=kv[2]
            if (kv[1]=="mlkem_us") mlkem=kv[2]
            if (kv[1]=="psk_us")   psk=kv[2]
            if (kv[1]=="tail_us")  tail=kv[2]
            if (kv[1]=="encap_us") encap=kv[2]
            if (kv[1]=="tls_us")   tls=kv[2]
            if (kv[1]=="write_us") write=kv[2]
          }
          if (total != "") {
            printf "{\"side\":\"%s\",\"token\":%s,\"total_us\":%s,\"zk_us\":%s,\"mlkem_us\":%s,\"psk_us\":%s,\"tail_us\":%s,\"encap_us\":%s,\"tls_us\":%s,\"write_us\":%s}\n",
                   SIDE, token, total, zk, mlkem, psk, tail, encap, tls, write
          }
        }'
}

extract client  client  "$SINCE_EPOCH" >>"$OUT"
extract gateway gateway "$SINCE_EPOCH" >>"$OUT"

n_client=$(grep -c '"side":"client"'  "$OUT" || true)
n_gw=$(    grep -c '"side":"gateway"' "$OUT" || true)
printf '{"scale_summary":{"N":%d,"n_client_timing":%d,"n_gateway_timing":%d,"wall_us":%d}}\n' \
    "$N" "$n_client" "$n_gw" "$wall_us" >>"$OUT"
echo "==> scale-driver N=$N: client=$n_client gateway=$n_gw wall=${wall_us}µs → $OUT"
