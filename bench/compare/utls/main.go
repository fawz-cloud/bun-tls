// go-utls side of bench/compare: utls HelloChrome_Auto (ALPN forced to http/1.1, since
// net/http cannot speak h2 over a utls conn) under net/http with Chrome-like headers.
// Usage: utls <scenario> <url> <n> <warm> <arg> <verify>; prints one JSON line (see run.ts).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	utls "github.com/refraction-networking/utls"
)

var headers = [][2]string{
	{"sec-ch-ua", `"Chromium";v="133", "Not(A:Brand";v="99", "Google Chrome";v="133"`},
	{"sec-ch-ua-mobile", "?0"},
	{"sec-ch-ua-platform", `"Windows"`},
	{"upgrade-insecure-requests", "1"},
	{"user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"},
	{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"},
	{"sec-fetch-site", "none"},
	{"sec-fetch-mode", "navigate"},
	{"sec-fetch-user", "?1"},
	{"sec-fetch-dest", "document"},
	{"accept-encoding", "gzip, deflate, br, zstd"},
	{"accept-language", "en-US,en;q=0.9"},
	{"priority", "u=0, i"},
}

func dial(verify bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		raw, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		host, _, _ := net.SplitHostPort(addr)
		spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
		if err != nil {
			raw.Close()
			return nil, err
		}
		for _, e := range spec.Extensions {
			if a, ok := e.(*utls.ALPNExtension); ok {
				a.AlpnProtocols = []string{"http/1.1"}
			}
		}
		c := utls.UClient(raw, &utls.Config{ServerName: host, InsecureSkipVerify: !verify}, utls.HelloCustom)
		if err := c.ApplyPreset(&spec); err != nil {
			raw.Close()
			return nil, err
		}
		if err := c.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, err
		}
		return c, nil
	}
}

// CPU cycles of the whole process (all threads; run.ts converts to ms), a QPC clock (Go's
// time.Now on Windows only moves with the timer tick) and the working set, from the OS.
var (
	k32    = syscall.NewLazyDLL("kernel32.dll")
	qpct   = k32.NewProc("QueryProcessCycleTime")
	qpc    = k32.NewProc("QueryPerformanceCounter")
	getPMI = syscall.NewLazyDLL("psapi.dll").NewProc("GetProcessMemoryInfo")
	qpf    = func() float64 {
		var f int64
		k32.NewProc("QueryPerformanceFrequency").Call(uintptr(unsafe.Pointer(&f)))
		return float64(f)
	}()
)

func cycles() float64 {
	h, _ := syscall.GetCurrentProcess()
	var c uint64
	qpct.Call(uintptr(h), uintptr(unsafe.Pointer(&c)))
	return float64(c)
}

func nowMs() float64 {
	var c int64
	qpc.Call(uintptr(unsafe.Pointer(&c)))
	return float64(c) * 1000 / qpf
}

func mem() (ws, peak float64) {
	h, _ := syscall.GetCurrentProcess()
	var m struct {
		cb, faults                              uint32
		peakWS, ws, qpp, qp, qpnp, qnp, pf, ppf uintptr
	}
	m.cb = uint32(unsafe.Sizeof(m))
	getPMI.Call(uintptr(h), uintptr(unsafe.Pointer(&m)), uintptr(m.cb))
	return float64(m.ws), float64(m.peakWS)
}

func main() {
	scen, url := os.Args[1], os.Args[2]
	n, _ := strconv.Atoi(os.Args[3])
	warm, _ := strconv.Atoi(os.Args[4])
	arg, _ := strconv.Atoi(os.Args[5])
	verify := os.Args[6] == "1"

	client := func(keepAlive bool, conc int) *http.Client {
		return &http.Client{Transport: &http.Transport{
			DialTLSContext: dial(verify), DisableKeepAlives: !keepAlive,
			MaxIdleConnsPerHost: conc + 1, DisableCompression: true,
		}}
	}
	do := func(c *http.Client, method string, body []byte) int {
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, _ := http.NewRequest(method, url, rd)
		for _, h := range headers {
			req.Header.Set(h[0], h[1])
		}
		res, err := c.Do(req)
		if err != nil {
			panic(err)
		}
		b, _ := io.ReadAll(res.Body) // buffer the body like the other clients do
		res.Body.Close()
		return len(b)
	}
	timed := func(fn func(), n, warm int) (med, cpu, wall float64) {
		for i := 0; i < warm; i++ {
			fn()
		}
		t := make([]float64, n)
		c0, w0 := cycles(), nowMs()
		for i := range t {
			a := nowMs()
			fn()
			t[i] = nowMs() - a
		}
		sort.Float64s(t)
		return t[n/2], cycles() - c0, nowMs() - w0
	}

	{ // setup: everything loaded and one handshake done before measuring idle memory
		c := client(false, 1)
		do(c, "GET", nil)
	}
	idle, _ := mem()

	var v, cpu, wall, units float64
	switch scen {
	case "fresh", "reuse":
		c := client(scen == "reuse", 1)
		v, cpu, wall = timed(func() { do(c, "GET", nil) }, n, warm)
		units = float64(n)
	case "tp":
		run := func(total int) float64 {
			c := client(true, arg)
			var next int64
			var wg sync.WaitGroup
			t := nowMs()
			for i := 0; i < arg; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for atomic.AddInt64(&next, 1) <= int64(total) {
						do(c, "GET", nil)
					}
				}()
			}
			wg.Wait()
			sec := (nowMs() - t) / 1000
			c.CloseIdleConnections()
			return sec
		}
		run(warm)
		c0, w0 := cycles(), nowMs()
		sec := run(n)
		cpu, wall = cycles()-c0, nowMs()-w0
		v, units = float64(n)/sec, float64(n)
	case "up":
		body := bytes.Repeat([]byte("A"), arg<<20)
		c := client(true, 1)
		med, c1, w1 := timed(func() { do(c, "POST", body) }, n, warm)
		mb := float64(len(body)) / 1e6
		v, cpu, wall, units = mb/(med/1000), c1, w1, mb*float64(n)
	case "down":
		c := client(true, 1)
		size := do(c, "GET", nil)
		med, c1, w1 := timed(func() { do(c, "GET", nil) }, n, warm)
		mb := float64(size) / 1e6
		v, cpu, wall, units = mb/(med/1000), c1, w1, mb*float64(n)
	}
	_, peak := mem()
	json.NewEncoder(os.Stdout).Encode(map[string]float64{"v": v, "cyc": cpu, "wall": wall, "n": units, "idle": idle, "peak": peak})
}
