# M-7 concurrency: n=4, 30 round(s), variant zk-pq

120/120 handshakes succeeded (0 failed) in 40.2s. Host load 0.11 to 0.25 on 8 threads. Commit `929333d232ff`, 3 dirty file(s).

## Handshake latency (first round trip minus steady median), ms

| n | min | median | mean | max |
| --- | --- | --- | --- | --- |
| 120 | 3.15 | 5.18 | 5.17 | 7.35 |

## Success by n

| n | trials | succeeded |
| --- | --- | --- |
| 4 | 120 | 120 |

Trials with exactly one client and one gateway [timing] line: 120 of 120 succeeded (the phase breakdown below is over these only).

## Client phases, ms

| phase | n | median | mean | max |
| --- | --- | --- | --- | --- |
| encap | 120 | 0.076 | 0.094 | 0.491 |
| psk | 120 | 0.036 | 0.076 | 0.920 |
| tail | 120 | 0.001 | 0.001 | 0.019 |
| tls | 120 | 2.123 | 2.164 | 3.184 |
| total | 120 | 2.450 | 2.504 | 3.554 |
| write | 120 | 0.025 | 0.021 | 0.095 |
| zk | 120 | 0.047 | 0.060 | 0.222 |

## Gateway phases, ms

| phase | n | median | mean | max |
| --- | --- | --- | --- | --- |
| decap | 120 | 0.089 | 0.117 | 0.626 |
| peer | 120 | 0.063 | 0.099 | 0.653 |
| total | 120 | 1.131 | 1.238 | 3.545 |
| verify | 120 | 0.102 | 0.166 | 0.538 |
| wait_ct | 120 | 0.001 | 0.018 | 1.144 |

