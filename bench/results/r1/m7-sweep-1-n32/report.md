# M-7 concurrency: n=32, 30 round(s), variant zk-pq

960/960 handshakes succeeded (0 failed) in 76.6s. Host load 0.58 to 0.93 on 8 threads. Commit `929333d232ff`, 6 dirty file(s).

## Handshake latency (first round trip minus steady median), ms

| n | min | median | mean | max |
| --- | --- | --- | --- | --- |
| 960 | 2.10 | 6.41 | 7.24 | 24.07 |

## Success by n

| n | trials | succeeded |
| --- | --- | --- |
| 32 | 960 | 960 |

Trials with exactly one client and one gateway [timing] line: 960 of 960 succeeded (the phase breakdown below is over these only).

## Client phases, ms

| phase | n | median | mean | max |
| --- | --- | --- | --- | --- |
| encap | 960 | 0.077 | 0.153 | 4.889 |
| psk | 960 | 0.042 | 0.370 | 8.989 |
| tail | 960 | 0.001 | 0.002 | 0.392 |
| tls | 960 | 2.901 | 3.476 | 16.882 |
| total | 960 | 3.857 | 4.551 | 20.691 |
| write | 960 | 0.026 | 0.045 | 3.271 |
| zk | 960 | 0.045 | 0.132 | 3.860 |

## Gateway phases, ms

| phase | n | median | mean | max |
| --- | --- | --- | --- | --- |
| decap | 960 | 0.088 | 0.108 | 0.502 |
| peer | 960 | 0.061 | 0.076 | 0.464 |
| total | 960 | 0.431 | 0.628 | 3.787 |
| verify | 960 | 0.103 | 0.157 | 0.503 |
| wait_ct | 960 | 0.001 | 0.036 | 2.547 |

