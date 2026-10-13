
### Speed (median of rounds)

| | bun-tls | impers (node) | impers (bun) | curl_cffi | go-utls |
|---|---|---|---|---|---|
| latency, new connection (ms) | **4.59** | 5.65 | 5.28 | 5.09 | 5.48 |
| latency, reused connection (ms) | **0.07** | 0.28 | 0.19 | 0.24 | 0.10 |
| throughput, 10 concurrent (req/s) | **31331** | 2779 | 4410 | 4383 | 30586 |
| throughput, 100 concurrent (req/s) | **16022** | 2834 | 6234 | 4300 | fail |
| upload 10 MiB (MB/s) | 415 | 1053 | 1065 | **1213** | 1091 |
| download 10 MiB (MB/s) | **501** | 407 | 448 | 250 | 263 |
| remote latency, new connection (ms) | **83.75** | 90.84 | 85.05 | 94.61 | 107.73 |
| remote latency, reused connection (ms) | 30.59 | **25.07** | 33.31 | 30.17 | 29.80 |

### CPU (process CPU time per unit, all threads)

| | bun-tls | impers (node) | impers (bun) | curl_cffi | go-utls |
|---|---|---|---|---|---|
| latency, new connection (ms CPU / request) | 2.42 | 2.43 | 2.53 | **2.13** | 2.68 |
| latency, reused connection (µs CPU / request) | **65** | 323 | 206 | 202 | 86 |
| throughput, 10 concurrent (µs CPU / request) | **48** | 367 | 261 | 221 | 108 |
| throughput, 100 concurrent (µs CPU / request) | **81** | 353 | 201 | 223 | fail |
| upload 10 MiB (ms CPU / MB) | 1.04 | 1.10 | 1.07 | **0.77** | 0.90 |
| download 10 MiB (ms CPU / MB) | **2.31** | 2.44 | 2.57 | 3.09 | 2.86 |
| remote latency, new connection (ms CPU / request) | **5.66** | 14.77 | 14.77 | 13.55 | 9.57 |
| remote latency, reused connection (µs CPU / request) | 1105 | 1105 | 1690 | 628 | **290** |

### CPU cores busy during throughput (CPU time ÷ wall time)

| | bun-tls | impers (node) | impers (bun) | curl_cffi | go-utls |
|---|---|---|---|---|---|
| throughput, 10 concurrent | 1.55 | 1.02 | 1.15 | **0.96** | 3.57 |
| throughput, 100 concurrent | 1.33 | 1.01 | 1.25 | **0.96** | fail |

### RAM (working set, MiB)

| | bun-tls | impers (node) | impers (bun) | curl_cffi | go-utls |
|---|---|---|---|---|---|
| idle after setup (median of all runs) | 43.1 | 52.4 | 41.7 | 30.6 | **11.2** |
| peak, latency, new connection | 63.2 | 55.2 | 51.5 | 30.5 | **18.5** |
| peak, latency, reused connection | 57.8 | 60.5 | 63.1 | 30.8 | **17.7** |
| peak, throughput, 10 concurrent | 71.5 | 65.2 | 95.1 | 32.4 | **20.2** |
| peak, throughput, 100 concurrent | 89.2 | 101.9 | 96.9 | **48.2** | fail |
| peak, upload 10 MiB | 86.4 | 68.6 | 60.6 | 40.7 | **23.5** |
| peak, download 10 MiB | 148.8 | 149.0 | 102.7 | 48.6 | **35.8** |

Failures:
- go-utls / throughput, 100 concurrent: exit 2: created by main.main.func5 in goroutine 1 | 	D:/projectmu/panel-v2/scratch/bun-tls/bench/compare/utls/main.go:173 +0x108
- go-utls / throughput, 100 concurrent: exit 2: created by main.main.func5 in goroutine 1 | 	D:/projectmu/panel-v2/scratch/bun-tls/bench/compare/utls/main.go:173 +0x108
- go-utls / throughput, 100 concurrent: exit 2: created by main.main.func5 in goroutine 1 | 	D:/projectmu/panel-v2/scratch/bun-tls/bench/compare/utls/main.go:173 +0x108
