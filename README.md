![bun-tls](assets/hero.svg)

# bun-tls

A TLS 1.3 / 1.2 HTTPS client written from scratch in TypeScript, with **control over the
TLS fingerprint** (JA3 / JA3N / JA4). The handshake is assembled by hand on a raw
`Bun.connect` socket; `node:crypto` is used only for primitives, so the ClientHello —
cipher list, extensions, order, GREASE — is yours to set. **No additional native
dependency**: no patched libcurl, no Python, no Dart, no `.dll` to build (it runs on Bun,
which brings its own OpenSSL for `node:crypto`).

```ts
import { request, clients } from './src';

const r = await request({ url: 'https://example.com/', fingerprint: clients.chrome() });
console.log(r.status, r.ja3nHash); // matches the published Chrome 131 JA3N
```

## Install

```bash
bun add github:fawz-cloud/bun-tls   # or: git clone, then import from ./src
```

Requires Bun ≥ 1.1. No build step.

## Quick start

```ts
import { request, Session, clients, fromJa3 } from './src';

// one-shot (certificate verified by default)
const r = await request({ url: 'https://api.github.com/' });
console.log(r.status, r.json(), r.ja3, r.ja4);

// impersonate a browser fingerprint
await request({ url: 'https://example.com/', fingerprint: clients.firefox() });

// …or a coherent persona: TLS + HTTP/2 + header order + User-Agent all match one browser,
// and the raw JA3 rotates each request so there is no fixed JA3 to block-list
await request({ url: 'https://example.com/', persona: 'chrome' });

// HTTP/2, TLS 1.2, a raw JA3, a proxy
await request({ url: 'https://nghttp2.org/', http2: true });
await request({ url: 'https://tls-v1-2.badssl.com:1012/', tls12: true });
await request({ url, fingerprint: fromJa3('771,4865-4866-4867,0-23-65281-10-11-…,29-23-24,0', { grease: true }) });
await request({ url, proxy: 'socks5://user:pass@host:1080' });

// a session: cookies, redirects, keep-alive, resumption
const s = new Session();
await s.get('https://example.com/login');
await s.post('https://example.com/do', { body: 'x=1' });
s.close();
```

## Features

- **Coherent personas** — `persona: 'chrome'` sets the TLS fingerprint, the HTTP/2 (Akamai)
  fingerprint, and the HTTP header order + User-Agent to **one matching browser**, and rotates
  the raw JA3 every connection so there is no fixed JA3 to block-list. That cross-layer match —
  TLS *and* h2 *and* headers agreeing — is exactly what anti-bot WAFs check, and what most
  fingerprint-spoofing clients get wrong. ([details](DOCS.md#personas))
- **Fingerprint control** — JA3 / JA3N / JA4 computed from the ClientHello actually sent;
  presets whose JA3/JA3N match published Chrome 131 / Firefox 148 / dart:io, plus
  `fromJa3()` for anything else.
- **TLS 1.3** (default) and **TLS 1.2** (`tls12: true`, ECDHE + AEAD) — keep-alive, 1-RTT
  resumption, opt-in 0-RTT, HelloRetryRequest, KeyUpdate, X25519 / P-256 / P-384 and the
  post-quantum **X25519MLKEM768** hybrid, RFC 8879 cert decompression, optional mTLS.
- **HTTP/1.1 and HTTP/2** — h2 with HPACK, flow control, Chrome's h2 fingerprint, and
  request multiplexing over one connection via `new Session({ http2: true })`.
- **Certificate verification** on by default (CA-constrained chain, hostname + IP SANs,
  path-building); optional **OCSP** revocation (stapling + AIA fetch); cookie jar with
  Public Suffix List; HTTP and SOCKS5 proxies; gzip / deflate / br / zstd.

**No additional native dependency** — a TypeScript source tree on Bun. From-scratch TLS,
**not audited**.

## Documentation

**Full API reference → [DOCS.md](DOCS.md)** — every option, `Session`, fingerprints,
TLS features, OCSP, HTTP/2, proxies, cookies, the low-level API and the architecture.

## Benchmarks

![benchmark](assets/benchmark.svg)

Reproducible, not hand-picked — scripts in `bench/` (see [DOCS.md](DOCS.md#testing)). One
interleaved run on localhost (Bun 1.4.2, curl_cffi 0.15.0, AES-128-GCM):

| scenario | bun-tls | curl_cffi |
|---|---|---|
| latency, fresh connection | 3.4 ms | 4.7 ms |
| latency, reused connection | 0.04 ms | 0.25 ms |
| throughput, 1 connection | 11,618 req/s | 2,227 req/s |
| throughput, 10 concurrent | 17,029 req/s | 3,020 req/s |
| throughput, 50 concurrent | 5,848 req/s | 1,320 req/s |
| upload 10 MB, reused | ~350 MB/s | ~420 MB/s |

On this localhost setup bun-tls is faster for one-shot and concurrent requests; curl keeps
an edge on bulk upload (native AEAD). The numbers do **not** isolate a cause (both use
connection reuse), and over a real network latency is round-trip-bound and the two converge.
Run the scripts on your own machine.

## How it compares

![comparison](assets/comparison.svg)

Clients that let you shape the ClientHello — `curl_cffi` (patched libcurl) and `utls` (Go) —
ship a patched native library or are a Go package. The ones with nothing extra to install —
`fetch`/`undici`, `requests`/`httpx` — can't shape it. bun-tls fills that gap for Bun.

## Test

```bash
bun test/all.ts          # offline: crypto, chacha, resumption vs RFC vectors, cookies
bun test/all.ts --live   # + network: handshake, JA3/JA4 echo, POST, resumption, h2, OCSP, TLS 1.2
```

## License

MIT
