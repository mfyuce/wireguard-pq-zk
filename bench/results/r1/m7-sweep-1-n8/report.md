# M-7 concurrency: n=8, 30 round(s), variant zk-pq

240/240 handshakes succeeded (0 failed) in 45.5s. Host load 0.23 to 0.59 on 8 threads. Commit `929333d232ff`, 4 dirty file(s).

## Handshake latency (first round trip minus steady median), ms

| n | min | median | mean | max |
| --- | --- | --- | --- | --- |
| 240 | 3.19 | 6.38 | 6.46 | 11.20 |

## Success by n

| n | trials | succeeded |
| --- | --- | --- |
| 8 | 240 | 240 |

Trials with exactly one client and one gateway [timing] line: 240 of 240 succeeded (the phase breakdown below is over these only).

## Client phases, ms

| phase | n | median | mean | max |
| --- | --- | --- | --- | --- |
| encap | 240 | 0.076 | 0.102 | 0.980 |
| psk | 240 | 0.040 | 0.090 | 1.703 |
| tail | 240 | 0.001 | 0.002 | 0.126 |
| tls | 240 | 2.867 | 3.227 | 7.517 |
| total | 240 | 3.395 | 3.672 | 7.869 |
| write | 240 | 0.025 | 0.024 | 0.341 |
| zk | 240 | 0.046 | 0.071 | 1.320 |

## Gateway phases, ms

| phase | n | median | mean | max |
| --- | --- | --- | --- | --- |
| decap | 240 | 0.089 | 0.113 | 0.897 |
| peer | 240 | 0.065 | 0.086 | 0.491 |
| total | 240 | 0.704 | 1.009 | 4.768 |
| verify | 240 | 0.107 | 0.165 | 0.600 |
| wait_ct | 240 | 0.001 | 0.086 | 3.439 |

