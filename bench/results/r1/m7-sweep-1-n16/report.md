# M-7 concurrency: n=16, 30 round(s), variant zk-pq

480/480 handshakes succeeded (0 failed) in 55.3s. Host load 0.54 to 0.63 on 8 threads. Commit `929333d232ff`, 5 dirty file(s).

## Handshake latency (first round trip minus steady median), ms

| n | min | median | mean | max |
| --- | --- | --- | --- | --- |
| 480 | 2.46 | 6.51 | 6.71 | 15.37 |

## Success by n

| n | trials | succeeded |
| --- | --- | --- |
| 16 | 480 | 480 |

Trials with exactly one client and one gateway [timing] line: 480 of 480 succeeded (the phase breakdown below is over these only).

## Client phases, ms

| phase | n | median | mean | max |
| --- | --- | --- | --- | --- |
| encap | 480 | 0.076 | 0.104 | 0.808 |
| psk | 480 | 0.041 | 0.158 | 3.864 |
| tail | 480 | 0.001 | 0.001 | 0.004 |
| tls | 480 | 2.882 | 3.248 | 7.626 |
| total | 480 | 3.506 | 3.851 | 11.616 |
| write | 480 | 0.014 | 0.041 | 2.290 |
| zk | 480 | 0.045 | 0.091 | 3.546 |

## Gateway phases, ms

| phase | n | median | mean | max |
| --- | --- | --- | --- | --- |
| decap | 480 | 0.089 | 0.116 | 0.529 |
| peer | 480 | 0.062 | 0.087 | 0.544 |
| total | 480 | 0.624 | 0.889 | 3.833 |
| verify | 480 | 0.128 | 0.177 | 0.796 |
| wait_ct | 480 | 0.001 | 0.053 | 1.533 |

