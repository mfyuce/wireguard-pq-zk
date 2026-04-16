#!/bin/bash
# Drive N parallel handshakes against the same wgzk daemon pair and collect
# per-handshake timing. Run inside the CLIENT VM after `scale-setup.sh N` has
# provisioned the extra peers on both sides. The single client daemon and
# single gateway daemon handle 2N concurrent NEED_PROOF events via Tokio tasks;
# each event emits one `[timing]` line (µs resolution) to journalctl.
#
# Usage (in-VM): sudo scale-run.sh N [OUT]
#                  N   — number of concurrent handshakes (must match setup)
#                  OUT — output JSONL path (default /tmp/scale-N.jsonl)
#
# Methodology:
#   t0 = journald cursor before we trigger
#   For i in 0..N-1 (all in parallel, backgrounded):
#     - Force handshake rekey: `wg set wg1l peer <pub> remove && add ... endpoint`
#       This invalidates the prior session; next outbound packet triggers NEED_PROOF.
#     - `ping -c 1 -W 3 -I 10.10.10.<100+i> 10.20.10.<100+i>` to force outbound.
#   wait
#   Collect [timing] lines from journalctl since t0; decorate with trial index;
#   emit JSONL with aggregate wall-clock.
#
# Note: the client daemon sees N client-side [timing] lines. The gateway daemon
# separately sees N gateway-side [timing] lines. We capture the client-side
# view here (same as run-trials.sh); gateway-side task-clock is captured by
# scale-run-cpu.sh if CPU attribution is needed.
set -euo pipefail

N="${1:-64}"
OUT="${2:-/tmp/scale-$N.jsonl}"
KEYS=/vagrant/vagrant/keys/scale

: >"$OUT"

# Cursor before we trigger — everything after this is ours.
CURSOR=$(journalctl -u wgzk -n0 --show-cursor -o cat 2>/dev/null | tail -1 | sed 's/^-- cursor: //')

t_start_ns=$(date +%s%N)

trigger_one() {
    local i="$1"
    local OFFSET=$((100 + i))
    local MY_IP="10.10.10.$OFFSET"
    local DST_IP="10.20.10.$OFFSET"
    local PEER_PUB; PEER_PUB="$(cat "$KEYS/pub_r_$i")"
    # Force fresh handshake by removing and re-adding the peer.
    wg set wg1l peer "$PEER_PUB" remove 2>/dev/null || true
    wg set wg1l peer "$PEER_PUB" \
        endpoint 192.168.100.1:51921 \
        allowed-ips "$DST_IP/32" >/dev/null
    ip route replace "$DST_IP/32" dev wg1l 2>/dev/null || true
    ping -c 1 -W 3 -I "$MY_IP" "$DST_IP" >/dev/null 2>&1 || true
}

# Fire all N in parallel.
for i in $(seq 0 $((N-1))); do
    trigger_one "$i" &
done
wait

t_end_ns=$(date +%s%N)
wall_us=$(( (t_end_ns - t_start_ns) / 1000 ))

# Give daemon a brief settle window so any straggling [timing] makes journald.
sleep 0.3

# Extract [timing] lines from journald since our cursor, emit as JSONL.
if [ -n "$CURSOR" ]; then
    JARGS=(--after-cursor "$CURSOR")
else
    JARGS=(--since "@$(( t_start_ns / 1000000000 - 1 ))")
fi

journalctl -u wgzk "${JARGS[@]}" -o cat | awk -v OUT="$OUT" '
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
      printf "{\"token\":%s,\"total_us\":%s,\"zk_us\":%s,\"mlkem_us\":%s,\"psk_us\":%s,\"tail_us\":%s,\"encap_us\":%s,\"tls_us\":%s,\"write_us\":%s}\n",
             token, total, zk, mlkem, psk, tail, encap, tls, write >> OUT
    }
  }
'

n_timing=$(wc -l <"$OUT")
printf '{"scale_summary":{"N":%d,"n_timing":%d,"wall_us":%d}}\n' "$N" "$n_timing" "$wall_us" >>"$OUT"
echo "==> scale-run N=$N: collected $n_timing [timing] lines, wall=${wall_us}µs → $OUT"
