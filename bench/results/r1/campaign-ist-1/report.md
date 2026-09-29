## Handshake latency (ms): first packet to its reply, minus the steady round trip

| run | system | blocks | trials | succeeded | failed | host load, lowest to highest | threads |
|---|---|---|---|---|---|---|---|
| wireguard | wireguard | 10 | 1000 | 1000 | 0 | 0.02 to 0.51 | 8 |
| wireguard-psk | wireguard-psk | 10 | 1000 | 1000 | 0 | 0.0 to 0.28 | 8 |
| rosenpass | rosenpass | 10 | 1000 | 1000 | 0 | 0.0 to 0.24 | 8 |
| pq-wireguard | pq-wireguard | 10 | 1000 | 1000 | 0 | 0.0 to 0.23 | 8 |
| wgzk-zk | wgzk-zk | 10 | 1000 | 1000 | 0 | 0.03 to 0.23 | 8 |
| wgzk-zkpq | wgzk-zkpq | 10 | 1000 | 1000 | 0 | 0.02 to 0.29 | 8 |

| run | n | median | p25 | p75 | p95 | p99 | max |
|---|---|---|---|---|---|---|---|
| wireguard | 1000 | 0.72 | 0.62 | 0.86 | 1.07 | 1.19 | 1.76 |
| wireguard-psk | 1000 | 0.65 | 0.53 | 0.77 | 0.96 | 1.14 | 1.43 |
| rosenpass | 1000 | 0.71 | 0.61 | 0.82 | 1.00 | 1.18 | 1.39 |
| pq-wireguard | 1000 | 1.10 | 0.96 | 1.21 | 1.38 | 1.50 | 2.07 |
| wgzk-zk | 1000 | 1.37 | 1.23 | 1.52 | 1.80 | 1.97 | 2.54 |
| wgzk-zkpq | 1000 | 3.68 | 3.47 | 3.90 | 4.18 | 4.56 | 5.27 |

## Steady round trip over the established session (ms)

| run | n | median | p25 | p75 | p95 | p99 | max |
|---|---|---|---|---|---|---|---|
| wireguard | 1000 | 1.01 | 0.95 | 1.06 | 1.13 | 1.20 | 1.28 |
| wireguard-psk | 1000 | 1.03 | 0.97 | 1.07 | 1.14 | 1.25 | 1.43 |
| rosenpass | 1000 | 1.02 | 0.95 | 1.07 | 1.14 | 1.22 | 1.32 |
| pq-wireguard | 1000 | 1.00 | 0.94 | 1.03 | 1.10 | 1.19 | 1.41 |
| wgzk-zk | 1000 | 1.01 | 0.96 | 1.06 | 1.14 | 1.20 | 1.43 |
| wgzk-zkpq | 1000 | 1.02 | 0.96 | 1.07 | 1.14 | 1.21 | 1.40 |

## Rosenpass: key exchange and cold start (ms)

| run, part | n | median | p25 | p75 | p95 | p99 | max |
|---|---|---|---|---|---|---|---|
| rosenpass, exchange | 1000 | 25.25 | 24.83 | 26.97 | 28.47 | 30.08 | 32.43 |
| rosenpass, exchange + handshake | 1000 | 26.01 | 25.52 | 27.60 | 29.25 | 30.79 | 33.35 |

## This design: phases inside the daemons (ms), trials with exactly one handshake


### wgzk-zk (1000 trials)

| side, phase | n | median | p25 | p75 | p95 | p99 | max |
|---|---|---|---|---|---|---|---|
| client, zk | 1000 | 0.05 | 0.05 | 0.05 | 0.11 | 0.13 | 0.18 |
| client, encap | 1000 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.07 |
| client, tls | 1000 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| client, write | 1000 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| client, psk | 1000 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| client, total | 1000 | 0.07 | 0.07 | 0.08 | 0.14 | 0.17 | 0.22 |
| gateway, wait_ct | 1000 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| gateway, verify | 1000 | 0.10 | 0.09 | 0.10 | 0.13 | 0.26 | 0.32 |
| gateway, decap | 1000 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| gateway, peer | 1000 | 0.08 | 0.07 | 0.08 | 0.12 | 0.12 | 0.15 |
| gateway, total | 1000 | 0.20 | 0.19 | 0.22 | 0.25 | 0.38 | 0.44 |
| outside the daemons | 1000 | 1.08 | 0.94 | 1.22 | 1.49 | 1.67 | 2.23 |

### wgzk-zkpq (1000 trials)

| side, phase | n | median | p25 | p75 | p95 | p99 | max |
|---|---|---|---|---|---|---|---|
| client, zk | 1000 | 0.05 | 0.05 | 0.05 | 0.11 | 0.13 | 0.15 |
| client, encap | 1000 | 0.07 | 0.07 | 0.08 | 0.14 | 0.16 | 0.20 |
| client, tls | 1000 | 2.13 | 2.02 | 2.24 | 2.40 | 2.54 | 3.07 |
| client, write | 1000 | 0.01 | 0.01 | 0.01 | 0.03 | 0.06 | 0.08 |
| client, psk | 1000 | 0.03 | 0.03 | 0.04 | 0.04 | 0.09 | 0.11 |
| client, total | 1000 | 2.35 | 2.23 | 2.47 | 2.64 | 2.80 | 3.40 |
| gateway, wait_ct | 1000 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.09 |
| gateway, verify | 1000 | 0.10 | 0.10 | 0.11 | 0.16 | 0.17 | 0.29 |
| gateway, decap | 1000 | 0.09 | 0.09 | 0.10 | 0.14 | 0.16 | 0.28 |
| gateway, peer | 1000 | 0.08 | 0.07 | 0.08 | 0.12 | 0.14 | 0.28 |
| gateway, total | 1000 | 0.33 | 0.30 | 0.36 | 0.41 | 0.47 | 0.64 |
| outside the daemons | 1000 | 1.00 | 0.84 | 1.16 | 1.35 | 1.54 | 1.80 |

## CPU time per handshake (ms)

Daemon: on-CPU time of its threads. All tasks: on-CPU time of every task of the machine,
idle window subtracted; it contains the driver of the trials. Interrupts: tick counts of
10 ms, idle window subtracted.

| run | machine | handshakes | daemon | all tasks | interrupts (ticks) | window (s) |
|---|---|---|---|---|---|---|
| wireguard | client | 1000 |  | 8.408 | 0.130 | 1138.4 |
| wireguard | gateway | 1000 |  | -2.318 | 0.130 | 1138.4 |
| wireguard-psk | client | 1000 |  | 8.895 | 0.060 | 1138.2 |
| wireguard-psk | gateway | 1000 |  | -2.168 | 0.130 | 1138.4 |
| rosenpass | client | 1000 |  | 67.818 | 0.140 | 1270.3 |
| rosenpass | gateway | 1000 | 8.039 | 6.072 | 0.150 | 1270.2 |
| pq-wireguard | client | 1000 |  | 50.344 | 0.070 | 1206.5 |
| pq-wireguard | gateway | 1000 |  | -1.899 | 0.180 | 1206.5 |
| wgzk-zk | client | 1000 | 0.194 | 16.519 | 0.100 | 1151.5 |
| wgzk-zk | gateway | 1000 | 0.605 | -1.575 | 0.130 | 1151.6 |
| wgzk-zkpq | client | 1000 | 0.830 | 4.747 | 0.148 | 1154.9 |
| wgzk-zkpq | gateway | 1000 | 1.208 | -0.674 | 0.240 | 1155.1 |
