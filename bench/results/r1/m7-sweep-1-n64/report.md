# M-7 concurrency: n=64, 30 round(s), variant zk-pq

1920/1920 handshakes succeeded (0 failed) in 121.6s. Host load 0.79 to 1.52 on 8 threads. Commit `929333d232ff`, 7 dirty file(s).

## Handshake latency (first round trip minus steady median), ms

| n | min | median | mean | max |
| --- | --- | --- | --- | --- |
| 1920 | 2.96 | 7.99 | 8.75 | 35.45 |

## Success by n

| n | trials | succeeded |
| --- | --- | --- |
| 64 | 1920 | 1920 |

Trials with exactly one client and one gateway [timing] line: 1920 of 1920 succeeded (the phase breakdown below is over these only).

## Client phases, ms

| phase | n | median | mean | max |
| --- | --- | --- | --- | --- |
| encap | 1920 | 0.075 | 0.191 | 6.033 |
| psk | 1920 | 0.043 | 0.429 | 13.334 |
| tail | 1920 | 0.001 | 0.005 | 6.069 |
| tls | 1920 | 3.688 | 4.343 | 29.270 |
| total | 1920 | 4.977 | 5.711 | 30.322 |
| write | 1920 | 0.012 | 0.057 | 4.955 |
| zk | 1920 | 0.045 | 0.117 | 6.330 |

## Gateway phases, ms

| phase | n | median | mean | max |
| --- | --- | --- | --- | --- |
| decap | 1920 | 0.087 | 0.103 | 0.671 |
| peer | 1920 | 0.061 | 0.073 | 0.453 |
| total | 1920 | 0.361 | 0.534 | 4.746 |
| verify | 1920 | 0.101 | 0.144 | 0.610 |
| wait_ct | 1920 | 0.001 | 0.025 | 2.830 |

