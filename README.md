![bun-tls](assets/hero.svg)

# bun-tls

A TLS 1.3 / 1.2 HTTPS client written from scratch in TypeScript, with **control over the
TLS fingerprint** (JA3 / JA3N / JA4). The handshake is assembled by hand on a raw
`Bun.connect` socket and only the crypto primitives are native — the operating system's own
library on Windows (CNG, through `bun:ffi`), Bun's `node:crypto` elsewhere — so the
ClientHello — cipher list, extensions, order, GREASE — is yours to set. **No additional
native dependency**: no patched libcurl, no Python, no Dart, no `.dll` to build or ship.

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
  presets whose JA3/JA3N match published Chrome 131 / Firefox 148 / dart:io, `fromJa3()` for
  a JA3 string, and **`fromClientHello()` to replay a captured ClientHello byte-for-byte**
  (exact extension order + bodies, not just the JA3) — capture a real client once, replay it.
- **TLS 1.3** (default) and **TLS 1.2** (ECDHE + AEAD; a 1.2-only server is answered in 1.2
  automatically, as browsers do, with downgrade protection) — keep-alive, 1-RTT
  resumption, opt-in 0-RTT, HelloRetryRequest, KeyUpdate, X25519 / P-256 / P-384 and the
  post-quantum **X25519MLKEM768** hybrid, RFC 8879 cert decompression, optional mTLS.
- **HTTP/1.1 and HTTP/2** — h2 with HPACK, flow control, Chrome's h2 fingerprint, and
  request multiplexing over one connection via `new Session({ http2: true })`.
- **HTTP/3 over QUIC** — a from-scratch QUIC v1 client (RFC 9000/9001/9114 + QPACK):
  `fetch(url, { http3: true })`. Verified against Cloudflare and nginx; QUIC crypto is
  byte-exact vs the RFC 9001 test vectors.
- **`fetch()` + streaming + WebSocket** — a Web-standard `fetch()` with a `ReadableStream`
  body and `persona`/`fingerprint` control, and `connectWebSocket()` (RFC 6455) over the
  same fingerprinted TLS.
- **Certificate verification** on by default (CA-constrained chain, hostname + IP SANs,
  path-building); optional **OCSP** revocation (stapling + AIA fetch); cookie jar with
  Public Suffix List; HTTP and SOCKS5 proxies; gzip / deflate / br / zstd.
- **Fingerprint proxy** — `bun src/cli.ts proxy --persona chrome`, then point any tool's
  `HTTP_PROXY` at it to borrow the persona from any language (the tool's own User-Agent never
  leaks over the browser TLS). ([details](DOCS.md#fingerprint-proxy-any-tool-any-language))
- **Scraping for LLMs** — `scrape(url, { as: 'llm' })` returns a page in the fewest tokens that
  keep its content: title, JSON-LD, and the main text with its headings, tables and code. Plus
  CSS and LLM extraction, `crawl` / `map` / `batch`, `search()` (web search → `{title, url,
  snippet}[]`, no API key), and an MCP server for agents. No browser.
  ([details](DOCS.md#scraping-for-llms))

**No additional native dependency** — a TypeScript source tree on Bun. From-scratch TLS,
**not audited**.

## Documentation

**Full API reference → [DOCS.md](DOCS.md)** — every option, `Session`, fingerprints,
TLS features, OCSP, HTTP/2, proxies, cookies, scraping and the MCP server, the low-level API
and the architecture.

## Benchmarks

![speed](bench/compare/svg/speed.svg)

Reproducible, not hand-picked — `bun bench/compare/run.ts` (see [DOCS.md](DOCS.md#testing)).
Five clients impersonating Chrome over HTTP/1.1 against a local Go TLS 1.3 server (remote rows:
example.com), every scenario in its own process, client order rotated per round, median of 3
rounds. Windows 11, i5-14450HX, Bun 1.4.3, curl_cffi 0.15.0, impers 0.1.2, utls 1.8.2:

| scenario | bun-tls | impers (node) | impers (bun) | curl_cffi | go-utls |
|---|---|---|---|---|---|
| latency, new connection | **4.59 ms** | 5.65 | 5.28 | 5.09 | 5.48 |
| latency, reused connection | **0.07 ms** | 0.28 | 0.19 | 0.24 | 0.10 |
| throughput, 10 concurrent | 31,331 req/s | 2,779 | 4,410 | 4,383 | 30,586 |
| throughput, 100 concurrent | **16,022 req/s** | 2,834 | 6,234 | 4,300 | fail |
| upload 10 MiB | 415 MB/s | 1,053 | 1,065 | **1,213** | 1,091 |
| download 10 MiB | **501 MB/s** | 407 | 448 | 250 | 263 |
| remote, new connection | 83.8 ms | 90.8 | 85.1 | 94.6 | 107.7 |
| remote, reused connection | 30.6 ms | 25.1 | 33.3 | 30.2 | 29.8 |

At 10 concurrent, bun-tls and go-utls are level: bun-tls is 2.4% ahead, which is inside the
run-to-run spread. go-utls gets there on 3.6 cores, bun-tls on ~1.5. Upload is the row where
bun-tls trails: its rounds were 1,007, 335 and 415 MB/s (a dedicated `bench/crypto/ab.ts` run
gives ~1,165 MB/s), and the cost is the socket write path rather than the crypto (1.04 ms
CPU/MB vs curl_cffi's 0.77). The remote rows have no winner. They are bound by round-trip time,
and each client's spread between rounds is wider than the gaps between clients: impers (node)
measured 31.1, 22.8 and 25.1 ms on reused connections. CPU and memory tables:
[bench/compare/out.md](bench/compare/out.md). Run the scripts on your own machine.

## Scraping for LLMs

```ts
import { scrape } from './src';

const r = await scrape('https://en.wikipedia.org/wiki/Transport_Layer_Security', { as: 'llm' });
r.llm;    // title, JSON-LD, main text — the URLs move to r.links
```

![tokens](assets/tokens.svg)

The same 8 pages in cl100k tokens: 63k for the `llm` view, 139k for Jina Reader, 127k for
readable Markdown with links. Every heading and every sentence of 60+ characters of that
Markdown is kept. Agents can use it as an MCP server:
`claude mcp add bun-tls -- bun /abs/path/to/bun-tls/src/mcp.ts`
([details](DOCS.md#scraping-for-llms)).

## How it compares

![comparison](assets/comparison.svg)

Clients that let you shape the ClientHello — `curl_cffi` (patched libcurl) and `utls` (Go) —
ship a patched native library or are a Go package. The ones with nothing extra to install —
`fetch`/`undici`, `requests`/`httpx` — can't shape it. bun-tls fills that gap for Bun.

## Test

```bash
bun test/all.ts          # offline: crypto, chacha, resumption vs RFC vectors, cookies, scrape rendering
bun test/all.ts --live   # + network: handshake, JA3/JA4 echo, POST, resumption, h2, OCSP, TLS 1.2
```

## License

MIT
