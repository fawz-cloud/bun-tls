// Benchmark server for bench/compare: TLS 1.3, HTTP/1.1 only, multi-core (net/http), so no
// client is capped by the server. GET / = 1 KiB, GET /10mb = 10 MiB chunked (no length set),
// GET /10mb-cl = 10 MiB with Content-Length, POST = received byte count.
// Usage: server <dir with cert.pem + key.pem>
package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

func main() {
	dir := os.Args[1]
	small := []byte(strings.Repeat("x", 1024))
	big := []byte(strings.Repeat("x", 10<<20))
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			n, _ := io.Copy(io.Discard, r.Body)
			fmt.Fprint(w, n)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		if r.URL.Path == "/10mb-cl" {
			w.Header().Set("Content-Length", fmt.Sprint(len(big)))
		}
		if r.URL.Path == "/10mb" || r.URL.Path == "/10mb-cl" {
			w.Write(big)
		} else {
			w.Write(small)
		}
	})
	srv := &http.Server{
		Addr:         ":48443",
		Handler:      h,
		TLSConfig:    &tls.Config{MinVersion: tls.VersionTLS13},
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}, // no h2: every client speaks HTTP/1.1
		ErrorLog:     log.New(io.Discard, "", 0),
	}
	log.Fatal(srv.ListenAndServeTLS(dir+"/cert.pem", dir+"/key.pem"))
}
