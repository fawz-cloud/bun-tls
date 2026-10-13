
### Speed (median of rounds)

| | bun-tls | impers (node) | impers (bun) | curl_cffi | go-utls |
|---|---|---|---|---|---|
| latency, new connection (ms) | **1.95** | 2.16 | 2.12 | 3.03 | 2.27 |
| latency, reused connection (ms) | **0.05** | 0.18 | 0.12 | 0.16 | 0.07 |
| throughput, 10 concurrent (req/s) | 26739 | 5469 | 5983 | 6346 | **39923** |
| throughput, 100 concurrent (req/s) | 19527 | 5112 | 8442 | 6636 | **29980** |
| upload 10 MiB (MB/s) | 1062 | 1308 | **1687** | 1546 | 1432 |
| download 10 MiB (MB/s) | 304 | **468** | 369 | 266 | 419 |
| remote latency, new connection (ms) | **77.29** | 92.81 | 83.42 | 83.57 | 84.74 |
| remote latency, reused connection (ms) | **28.66** | 29.29 | 29.18 | 28.95 | 29.49 |

### CPU (process CPU time per unit, all threads)

| | bun-tls | impers (node) | impers (bun) | curl_cffi | go-utls |
|---|---|---|---|---|---|
| latency, new connection (ms CPU / request) | 1.49 | **1.35** | 1.49 | 1.54 | 1.60 |
| latency, reused connection (µs CPU / request) | 66 | 226 | 147 | 149 | **59** |
| throughput, 10 concurrent (µs CPU / request) | **71** | 203 | 187 | 157 | 112 |
| throughput, 100 concurrent (µs CPU / request) | **99** | 216 | 155 | 150 | 340 |
| upload 10 MiB (ms CPU / MB) | 1.57 | 0.74 | 0.64 | **0.59** | 0.63 |
| download 10 MiB (ms CPU / MB) | 4.52 | 2.08 | **2.01** | 2.34 | 2.03 |
| remote latency, new connection (ms CPU / request) | **5.11** | 15.78 | 14.33 | 13.14 | 8.85 |
| remote latency, reused connection (µs CPU / request) | 1319 | 1171 | 1966 | 900 | **383** |

### CPU cores busy during throughput (CPU time ÷ wall time)

| | bun-tls | impers (node) | impers (bun) | curl_cffi | go-utls |
|---|---|---|---|---|---|
| throughput, 10 concurrent | 1.89 | 1.07 | 1.13 | **0.96** | 4.47 |
| throughput, 100 concurrent | 1.87 | 1.06 | 1.30 | **0.99** | 8.53 |

### RAM (working set, MiB)

| | bun-tls | impers (node) | impers (bun) | curl_cffi | go-utls |
|---|---|---|---|---|---|
| idle after setup (median of all runs) | 40.3 | 50.4 | 40.4 | 30.6 | **11.1** |
| peak, latency, new connection | 59.8 | 53.2 | 52.3 | 30.6 | **18.1** |
| peak, latency, reused connection | 55.7 | 58.5 | 64.0 | 30.8 | **17.5** |
| peak, throughput, 10 concurrent | 70.3 | 62.9 | 84.7 | 32.2 | **21.0** |
| peak, throughput, 100 concurrent | 80.3 | 98.6 | 90.3 | **47.8** | 95.8 |
| peak, upload 10 MiB | 68.8 | 65.4 | 58.0 | 40.6 | **23.5** |
| peak, download 10 MiB | 148.4 | 148.2 | 103.4 | 48.5 | **37.4** |

Failures:
- go-utls / throughput, 100 concurrent: exit 2: created by main.main.func5 in goroutine 1 | 	D:/projectmu/panel-v2/scratch/bun-tls/bench/compare/utls/main.go:173 +0x108
- go-utls / throughput, 100 concurrent: exit 2: created by main.main.func5 in goroutine 1 | 	D:/projectmu/panel-v2/scratch/bun-tls/bench/compare/utls/main.go:173 +0x108
