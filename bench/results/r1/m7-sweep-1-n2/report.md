# M-7 concurrency: n=2, 30 round(s), variant zk-pq

60/60 handshakes succeeded (0 failed) in 38.0s. Host load 0.11 to 0.12 on 8 threads. Commit `929333d232ff`, 2 dirty file(s).

## Handshake latency (first round trip minus steady median), ms

| n | min | median | mean | max |
| --- | --- | --- | --- | --- |
| 60 | 2.64 | 3.77 | 3.80 | 5.36 |

## Success by n

| n | trials | succeeded |
| --- | --- | --- |
| 2 | 60 | 60 |

Trials with exactly one client and one gateway [timing] line: 60 of 60 succeeded (the phase breakdown below is over these only).

## Client phases, ms

| phase | n | median | mean | max |
| --- | --- | --- | --- | --- |
| encap | 60 | 0.075 | 0.084 | 0.160 |
| psk | 60 | 0.043 | 0.061 | 0.505 |
| tail | 60 | 0.001 | 0.004 | 0.172 |
| tls | 60 | 1.925 | 1.978 | 2.650 |
| total | 60 | 2.239 | 2.282 | 2.949 |
| write | 60 | 0.020 | 0.022 | 0.103 |
| zk | 60 | 0.047 | 0.052 | 0.172 |

## Gateway phases, ms

| phase | n | median | mean | max |
| --- | --- | --- | --- | --- |
| decap | 60 | 0.090 | 0.103 | 0.311 |
| peer | 60 | 0.073 | 0.103 | 0.457 |
| total | 60 | 0.470 | 0.669 | 1.485 |
| verify | 60 | 0.097 | 0.148 | 0.641 |
| wait_ct | 60 | 0.001 | 0.003 | 0.109 |

