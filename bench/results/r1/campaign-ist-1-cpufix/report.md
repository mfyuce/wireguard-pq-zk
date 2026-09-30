## Handshake latency (ms): first packet to its reply, minus the steady round trip

| run | system | blocks | trials | succeeded | failed | host load, lowest to highest | threads |
|---|---|---|---|---|---|---|---|
| wireguard | wireguard | 5 | 500 | 500 | 0 | 0.01 to 0.62 | 8 |
| pq-wireguard | pq-wireguard | 5 | 500 | 500 | 0 | 0.02 to 0.27 | 8 |
| wgzk-zk | wgzk-zk | 5 | 500 | 500 | 0 | 0.01 to 0.27 | 8 |
| wgzk-zkpq | wgzk-zkpq | 5 | 500 | 500 | 0 | 0.01 to 0.18 | 8 |

| run | n | median | p25 | p75 | p95 | p99 | max |
|---|---|---|---|---|---|---|---|
| wireguard | 500 | 0.72 | 0.61 | 0.83 | 1.04 | 1.19 | 1.40 |
| pq-wireguard | 500 | 1.08 | 0.92 | 1.21 | 1.40 | 1.54 | 1.73 |
| wgzk-zk | 500 | 1.38 | 1.26 | 1.53 | 1.78 | 1.93 | 2.07 |
| wgzk-zkpq | 500 | 3.78 | 3.57 | 3.98 | 4.29 | 4.63 | 5.29 |

## Steady round trip over the established session (ms)

| run | n | median | p25 | p75 | p95 | p99 | max |
|---|---|---|---|---|---|---|---|
| wireguard | 500 | 1.02 | 0.96 | 1.07 | 1.14 | 1.21 | 1.33 |
| pq-wireguard | 500 | 1.00 | 0.94 | 1.04 | 1.10 | 1.15 | 1.28 |
| wgzk-zk | 500 | 1.02 | 0.96 | 1.07 | 1.14 | 1.18 | 1.28 |
| wgzk-zkpq | 500 | 1.03 | 0.96 | 1.07 | 1.14 | 1.29 | 1.40 |

## This design: phases inside the daemons (ms), trials with exactly one handshake


### wgzk-zk (500 trials)

| side, phase | n | median | p25 | p75 | p95 | p99 | max |
|---|---|---|---|---|---|---|---|
| client, zk | 500 | 0.05 | 0.05 | 0.05 | 0.12 | 0.13 | 0.16 |
| client, encap | 500 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.01 |
| client, tls | 500 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| client, write | 500 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| client, psk | 500 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| client, total | 500 | 0.07 | 0.07 | 0.08 | 0.15 | 0.17 | 0.20 |
| gateway, wait_ct | 500 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| gateway, verify | 500 | 0.10 | 0.09 | 0.10 | 0.13 | 0.16 | 0.29 |
| gateway, decap | 500 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| gateway, peer | 500 | 0.08 | 0.07 | 0.08 | 0.11 | 0.13 | 0.16 |
| gateway, total | 500 | 0.20 | 0.20 | 0.22 | 0.25 | 0.30 | 0.48 |
| outside the daemons | 500 | 1.09 | 0.97 | 1.23 | 1.44 | 1.64 | 1.79 |

### wgzk-zkpq (500 trials)

| side, phase | n | median | p25 | p75 | p95 | p99 | max |
|---|---|---|---|---|---|---|---|
| client, zk | 500 | 0.05 | 0.05 | 0.05 | 0.11 | 0.13 | 0.14 |
| client, encap | 500 | 0.07 | 0.07 | 0.08 | 0.14 | 0.17 | 0.19 |
| client, tls | 500 | 2.15 | 2.04 | 2.26 | 2.39 | 2.50 | 2.90 |
| client, write | 500 | 0.01 | 0.01 | 0.01 | 0.03 | 0.04 | 0.09 |
| client, psk | 500 | 0.03 | 0.03 | 0.04 | 0.04 | 0.09 | 0.10 |
| client, total | 500 | 2.38 | 2.26 | 2.50 | 2.61 | 2.77 | 3.14 |
| gateway, wait_ct | 500 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.05 |
| gateway, verify | 500 | 0.10 | 0.10 | 0.11 | 0.16 | 0.17 | 0.27 |
| gateway, decap | 500 | 0.09 | 0.09 | 0.10 | 0.14 | 0.15 | 0.17 |
| gateway, peer | 500 | 0.08 | 0.07 | 0.08 | 0.13 | 0.15 | 0.31 |
| gateway, total | 500 | 0.33 | 0.30 | 0.37 | 0.43 | 0.48 | 0.56 |
| outside the daemons | 500 | 1.06 | 0.90 | 1.20 | 1.44 | 1.65 | 1.99 |

## CPU time per handshake (ms)

Daemon: on-CPU time of its threads. All tasks: on-CPU time of every task of the machine,
idle window subtracted; it contains the driver of the trials. Interrupts: tick counts of
10 ms, idle window subtracted.

| run | machine | handshakes | daemon | all tasks | interrupts (ticks) | window (s) |
|---|---|---|---|---|---|---|
| wireguard | client | 500 |  | 9.664 | 0.080 | 572.8 |
| wireguard | gateway | 500 |  | -1.186 | 0.120 | 572.9 |
| pq-wireguard | client | 500 |  | 49.901 | 0.100 | 603.8 |
| pq-wireguard | gateway | 500 |  | -1.323 | 0.160 | 603.9 |
| wgzk-zk | client | 500 | 0.196 | 17.891 | 0.100 | 580.2 |
| wgzk-zk | gateway | 500 | 0.624 | -0.198 | 0.180 | 580.3 |
| wgzk-zkpq | client | 500 | 0.837 | 18.374 | 0.180 | 580.1 |
| wgzk-zkpq | gateway | 500 | 1.217 | 0.275 | 0.240 | 580.1 |
