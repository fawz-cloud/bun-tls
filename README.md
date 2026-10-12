![bun-tls](assets/hero.svg)

# bun-tls

A TLS 1.3 HTTPS client written from scratch in TypeScript, with **control over the TLS
fingerprint** (JA3 / JA3N / JA4). The handshake is assembled by hand on a raw
`Bun.connect` socket; `node:crypto` is used only for primitives, so the ClientHello —
cipher list, extensions, order, GREASE — is yours to set. **No additional native
dependency**: no patched libcurl, no Python, no Dart, no `.dll` to build (it runs on Bun,
which brings its own OpenSSL for `node:crypto`).

```ts
import { request, clients } from './src';

const r = await request({ url: 'https://example.com/', fingerprint: clients.chrome() });
console.log(r.status, r.ja3nHash); // matches the published Chrome 131 JA3N
```

## Scope — read this first

- **"Matches a fingerprint" ≠ "is that client."** A JA3/JA4 summarizes only part of the
  ClientHello. The presets reproduce the JA3/JA3N of a given client version (verified
  against an echo server), not every byte of its handshake. `fromJa3()` has even less to
  work with — it rebuilds from a JA3 string, so it matches that JA3 and nothing more.
- **HTTP/1.1 only.** Browser presets advertise ALPN `http/1.1`. The JA3 still matches
  (ALPN is not in JA3); the JA4 ALPN byte and the real protocol do not.
- **TLS 1.3 by default; TLS 1.2 is opt-in** (`tls12: true`) for 1.2-only servers —
  ECDHE + AEAD (AES-GCM / ChaCha20-Poly1305) with extended master secret, no CBC or
  static-RSA. The ECDHE groups (X25519, P-256, P-384) are fully negotiable, including via
  HelloRetryRequest (1.3) when a server wants a group we only advertised. The post-quantum
  `X25519MLKEM768` and FFDHE groups are advertised but have no implementation, so a server
  that accepts *only* one of those cannot be reached.
- From-scratch TLS, **not audited.**

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

// a named preset
await request({ url: 'https://example.com/', fingerprint: clients.firefox() });

// HTTP/2 (ALPN h2, falls back to h1 if the server declines)
await request({ url: 'https://nghttp2.org/', http2: true });

// TLS 1.2 (ECDHE + AEAD) for a 1.2-only server
await request({ url: 'https://tls-v1-2.badssl.com:1012/', tls12: true });

// reproduce an arbitrary JA3 (full, runnable value)
await request({
  url: 'https://example.com/',
  fingerprint: fromJa3('771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-16-5-13-18-51-45-43-27,29-23-24,0', { grease: true }),
});

// through a proxy — HTTP CONNECT or SOCKS5
await request({ url: 'https://host/', proxy: 'http://user:pass@host:8080' });
await request({ url: 'https://host/', proxy: 'socks5://user:pass@host:1080' });

// a session: cookies, redirects, keep-alive, resumption
const s = new Session();
await s.get('https://example.com/login');
await s.post('https://example.com/do', { body: 'x=1' });
s.close();
```

`request(options)` → `ClientResponse`: `url`, `method?`, `headers?`, `body?`,
`fingerprint?`, `proxy?`, `verify?` (default true), `ocsp?` (`'off'`\|`'soft'`\|`'hard'`,
default `'off'`), `tls12?` (speak TLS 1.2 instead of 1.3), `timeoutMs?`. Response adds `ja3`,
`ja3Hash`, `ja3n`, `ja3nHash`, `ja4`, `alpn` on top of `status`, `headers`, `body`,
`text()`, `json()`.

## Fingerprints

- **`fromJa3(ja3, opts?)`** — rebuild from a JA3 string (hash-exact to that JA3; cipher
  and extension order preserved; optional GREASE). A JA3 omits ALPN, sigalgs and key-share
  contents, so pass them via `opts` when they matter.
- **`clients.*`** — presets:
  - `chrome`, `edge`, `firefox`, `dart`: built from a ClientHello spec (utls
    `u_parrots.go` for browsers, a live capture for dart:io). Their JA3/JA3N match the
    published values; `chrome`/`edge` permute extensions per connection, so the raw JA3
    varies while the JA3N (sorted) is stable.
  - `safari`, `okhttp`: rebuilt from a reference JA3 via `fromJa3` (see the caveat above).

Custom fingerprints are an array of extension builders, in wire order:

```ts
import { ext, consts } from './src';
const fp = {
  ciphers: [consts.Cipher.TLS_AES_128_GCM_SHA256, consts.Cipher.TLS_CHACHA20_POLY1305_SHA256],
  keyShareGroups: [consts.Group.x25519],
  extensions: [ ext.serverName(), ext.supportedGroups([consts.Group.x25519]),
    ext.signatureAlgorithms([0x0403, 0x0804]), ext.supportedVersions(),
    ext.pskKeyExchangeModes([1]), ext.keyShare(), ext.alpn(['http/1.1']) ],
};
```

## Keep-alive, resumption & 0-RTT

![handshake](assets/handshake.svg)

`Session` reuses work across requests:

- **Keep-alive** (on): connections are pooled per host, so only the first request pays a
  handshake.
- **Session resumption** (on): `NewSessionTicket`s are cached; a new connection presents
  one as a `pre_shared_key` and resumes in 1-RTT, with no certificate exchange.
- **0-RTT early data** (`{ zeroRtt: true }`, **off by default**): a GET/HEAD rides in the
  ClientHello, saving a round trip. 0-RTT early data can be **replayed** by a network
  attacker — restricting it to GET/HEAD does not remove that risk, because whether a
  replay is harmless depends on the endpoint. Enable it only for endpoints where replay
  is safe. If the server declines, the request is resent over the completed handshake.

The resumption/0-RTT key schedule is checked byte-for-byte against the RFC 8448 §4 vectors
(`test/resumption.test.ts`).

## How it's built

![architecture](assets/architecture.svg)

Four layers, imports pointing down only: `core` (bytes + crypto) → `tls` (handshake,
records, cert verification, transport) → `fp` (presets, `fromJa3`) → `http` (`request`,
`Session`). ~2k lines; each module owns one concern and is tested on its own.

## Benchmarks

![benchmark](assets/benchmark.svg)

Reproducible, not hand-picked — the scripts are in `bench/`:

```bash
# one self-signed cert for the local server (verification is off for both clients)
openssl req -x509 -newkey rsa:2048 -nodes -keyout bench/key.pem -out bench/cert.pem \
  -days 7 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost"

bun bench/server.ts            # terminal 1
bun bench/bun.ts               # terminal 2 — bun-tls
python bench/curl_bench.py     # terminal 2 — curl_cffi (pip install curl_cffi)
```

Both use the same scenarios: a fresh `Session` per request for *fresh* latency, one
`Session`/`AsyncSession` for *reused* latency, uploads and throughput; throughput is 1000
requests at concurrency C; medians after a warmup. One interleaved run on localhost
(Bun 1.4.2, curl_cffi 0.15.0, AES-128-GCM):

| scenario | bun-tls | curl_cffi |
|---|---|---|
| latency, fresh connection | 3.4 ms | 4.7 ms |
| latency, reused connection | 0.04 ms | 0.25 ms |
| throughput, 1 connection | 11,618 req/s | 2,227 req/s |
| throughput, 10 concurrent | 17,029 req/s | 3,020 req/s |
| throughput, 50 concurrent | 5,848 req/s | 1,320 req/s |
| upload 10 MB, reused | ~350 MB/s | ~420 MB/s |

What this shows, and what it does not: on this localhost setup bun-tls is faster for
one-shot and concurrent requests, and curl keeps an edge on bulk upload (native AEAD).
These numbers do **not** isolate a cause — curl_cffi offers `AsyncSession` and connection
reuse (both used here), so the gap is not attributed to any single factor like the GIL.
Over a real network, latency is dominated by round-trips and the two converge. Run the
scripts on your own machine.

## How it compares

![comparison](assets/comparison.svg)

Clients that let you shape the ClientHello — `curl_cffi` (patched libcurl) and `utls`
(Go TLS library) — either ship a patched native library or are a Go package. The ones
with nothing extra to install — `fetch`/`undici`, `requests`/`httpx` — can't shape it.
bun-tls fills that gap for Bun, at the cost of HTTP/1.1 only.

## What it does well

- Control over JA3 / JA4; presets whose JA3/JA3N match published Chrome 131 / Firefox 148
  / dart:io values, plus `fromJa3()` for anything else.
- No additional native dependency — a TypeScript source tree on Bun.
- Keep-alive, 1-RTT resumption, optional 0-RTT (RFC 8448-checked key schedule),
  post-handshake KeyUpdate, and HelloRetryRequest — all handled.
- Key exchange over X25519 / P-256 / P-384 and the post-quantum X25519MLKEM768 hybrid,
  with HelloRetryRequest and RFC 8879 certificate decompression — the browser presets reach
  PQC-preferring CDNs with their real fingerprint. HTTP and SOCKS5 proxies; gzip/deflate/br/zstd.
- HTTP/2: ALPN h2, HPACK, flow control, Chrome's h2 fingerprint, and request multiplexing
  over one connection via `new Session({ http2: true })`.
- TLS 1.2 fallback (`tls12: true`): ECDHE + AEAD (AES-GCM / ChaCha20-Poly1305) with extended
  master secret and ServerKeyExchange-signature verification, for 1.2-only servers.
- Optional mutual-TLS servers complete (we answer a CertificateRequest).
- Certificate verification on by default (CA-constrained chain, hostname + IP SANs, path-building
  to a bundled root store); optional OCSP revocation (`ocsp: 'soft' | 'hard'`) — stapled response
  or AIA fetch, with responder-signature, CertID-binding and freshness checks; cookie jar with
  Public Suffix List + `__Host-`/`__Secure-` rules.
- Fast for one-shot and concurrent requests on the local benchmark; small, readable code.

## Limitations

- **TLS 1.2 is opt-in** via `request({ tls12: true })` — ECDHE + AEAD (AES-GCM /
  ChaCha20-Poly1305), extended master secret, OCSP; no CBC or static-RSA key exchange (so a
  1.2 server offering *only* those is not reachable — all modern ones offer ECDHE-AEAD). The
  default is TLS 1.3. **HTTP/2 works** via `request({ http2: true })`
  — ALPN h2, HPACK, flow control, verified against Cloudflare/Google/nghttp2. Its
  SETTINGS / WINDOW_UPDATE / pseudo-header order reproduce Chrome's h2 (Akamai) fingerprint
  `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`. `new Session({ http2: true })` keeps one
  h2 connection per host and **multiplexes** concurrent requests over it; the one-shot
  `request({ http2: true })` uses a fresh connection. HTTP/1.1 is the default.
- **Key exchange:** X25519, P-256, P-384, and the post-quantum **X25519MLKEM768** hybrid
  are negotiated (incl. via HelloRetryRequest). The Chrome/Firefox presets send the ML-KEM
  share, so they connect to PQC-preferring servers (current Cloudflare/Google). FFDHE groups
  are advertised for fingerprint fidelity but not implemented (no mainstream server requires
  them).
- **From-scratch TLS, not audited.** Certificate verification is implemented and on by
  default, but review `src/tls/verify.ts` before relying on it where correctness matters.
- **OCSP revocation is opt-in** (`ocsp: 'off'` by default). `'soft'` is browser-style — a
  confirmed `revoked` fails, but a missing or `unknown` status is tolerated. `'hard'` requires
  a good, in-date response (stapled, or fetched from the cert's AIA responder), so it fails on
  certs that carry no OCSP at all — including current Let's Encrypt, which retired OCSP in 2025.
  No CRL fallback.
- Certificate chain path-building anchors at the earliest chain cert signed by a known
  root (covers legacy cross-signed roots such as GlobalSign R1 / AAA Certificate
  Services). If verification fails on a host you trust, fix the trust chain — add the
  missing root to `cacert.pem` — rather than disabling verification.
- Bulk upload: a large body is streamed in backpressure-paced batches (overlaps encryption
  with the server read). On localhost, curl's native AES-NI + C socket path still leads raw
  bulk throughput — a JS + `node:crypto` ceiling, not a design flaw. On a real network,
  upload is bandwidth-bound and the two tie.

## Test

```bash
bun test/all.ts          # offline: crypto, chacha, resumption vs RFC vectors
bun test/all.ts --live   # + network: handshake, JA3/JA4 echo, POST, resumption
```

## License

MIT
