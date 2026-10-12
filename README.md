![bun-tls](assets/hero.svg)

# bun-tls

A TLS 1.3 HTTPS client written from scratch in TypeScript, with **full control over
the TLS fingerprint** (JA3 / JA3N / JA4). Like [`curl_cffi`](https://github.com/lexiforest/curl_cffi),
but pure Bun — **no Python, no Dart, no native `.dll`**. The handshake is hand-written
on a raw `Bun.connect` socket; `node:crypto` is used only for primitives, so every byte
of the ClientHello is yours to set.

```ts
import { request, clients } from './src';

const r = await request({ url: 'https://example.com/', fingerprint: clients.chrome() });
console.log(r.status, r.ja3nHash); // dee19b855b658c6aa0f575eda2525e19 — real Chrome 131
```

## Why

- **Exact fingerprints.** The ClientHello is assembled from a `Fingerprint` (cipher list
  + extension list, in wire order). JA3/JA4 are computed by parsing the bytes actually
  sent, and verified live against `tls.peet.ws`. The browser presets are transcribed
  byte-for-byte from [utls](https://github.com/refraction-networking/utls) and match the
  published values for Chrome 131, Firefox 148, and captured dart:io.
- **No native dependency.** Runs anywhere Bun runs. Nothing to compile, no `.so`/`.dll`,
  no Python runtime riding along.
- **Readable.** ~2k lines across small single-purpose modules — you can follow the whole
  handshake end to end.

## Features

- TLS 1.3 handshake from scratch (RFC 8446), validated against the RFC 8448 vectors.
- Ciphers: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 (pure TS, RFC 8439).
- Key exchange: X25519, secp256r1, secp384r1.
- `fromJa3("771,...")` to reproduce any target from a JA3 string.
- Browser/client presets with GREASE and Chrome-style extension permutation.
- HTTP/1.1: chunked, Content-Length, read-to-EOF, gzip/deflate/br.
- `Session`: cookie jar, redirects, connection pooling, resumption, 0-RTT.
- HTTP proxy (`CONNECT` tunnel + Basic auth).
- Certificate verification on by default (hostname SAN, validity, chain path-building to
  a bundled Mozilla root store, and CertificateVerify) — or `verify: false`.

## Quick start

```ts
import { request, Session, clients, fromJa3 } from './src';

// one-shot
const r = await request({ url: 'https://api.github.com/' });
console.log(r.status, r.json(), r.ja3, r.ja4);

// impersonate a named client
await request({ url: 'https://example.com/', fingerprint: clients.firefox() });

// reproduce an arbitrary JA3
await request({ url: 'https://example.com/', fingerprint: fromJa3('771,4865-4866-4867,0-23-10-11-16-...,29-23-24,0') });

// through a proxy, skip cert verify
await request({ url: 'https://host/', proxy: 'http://user:pass@host:8080', verify: false });

// a session (cookies, redirects, keep-alive, resumption all persist)
const s = new Session();
await s.get('https://example.com/login');
await s.post('https://example.com/do', { body: 'x=1' });
s.close();
```

`request(options)` → `ClientResponse`: `url`, `method?`, `headers?`, `body?`,
`fingerprint?`, `proxy?`, `verify?` (default true), `timeoutMs?`. Response adds
`ja3`, `ja3Hash`, `ja3n`, `ja3nHash`, `ja4`, `alpn` on top of `status`, `headers`,
`body`, `text()`, `json()`.

## Mimic any client

1. **`fromJa3(ja3)`** — paste any JA3 string; reproduced hash-exact, order preserved,
   optional GREASE.
2. **`clients.*`** — ready presets:
   - **Faithful** (`chrome`, `edge`, `firefox`, `dart`): transcribed from utls
     `u_parrots.go` (`HelloChrome_131`, `HelloFirefox_148`) and a live dart:io capture.
     They carry the post-quantum `X25519MLKEM768` group and GREASE ECH. `chrome`/`edge`
     permute their extensions per connection like real Chrome — so the raw JA3 varies,
     but the **JA3N** (sorted) is stable and matches the published value.
   - **Reference** (`safari`, `okhttp`): rebuilt from a reference JA3 via `fromJa3`.

Custom fingerprints are just an array of extension builders, in wire order:

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

`Session` makes repeat requests cheap three ways (all on by default):

1. **Keep-alive** — connections are pooled per host and reused, so only the first request
   to a host pays a handshake.
2. **Session resumption** — `NewSessionTicket`s are cached; a new connection presents one
   as a `pre_shared_key` and resumes in 1-RTT, with no certificate exchange.
3. **0-RTT early data** — when the ticket allows it, an idempotent request (GET/HEAD) is
   sent *with* the ClientHello, saving a round trip. Never used for POST (replay-unsafe);
   if the server declines, the request is transparently resent over the handshake.

The resumption/0-RTT key schedule is validated byte-for-byte against the RFC 8448 §4
vectors (`test/resumption.test.ts`). `new Session({ keepAlive: false })` or
`{ zeroRtt: false }` opt out; one-shot `request()` always uses a fresh connection.

## How it's built

![architecture](assets/architecture.svg)

Four layers, imports pointing downward only: `core` (bytes + crypto) → `tls` (handshake,
records, cert verification, transport) → `fp` (fingerprint presets, `fromJa3`) → `http`
(`request`, `Session`). Each module owns one concern and is independently testable.

## Performance

![benchmark](assets/benchmark.svg)

Measured against curl_cffi 0.15.0 on the same machine (Bun 1.4.2, Windows).

| scenario | bun-tls | curl_cffi | note |
|---|---|---|---|
| localhost latency, fresh handshake | **2.3 ms** | 4–14 ms | we win — no Python/cffi per-request cost |
| localhost latency, reused conn | **0.06 ms** | 0.12–0.21 ms | we win |
| throughput, keep-alive, 10 concurrent | **14,193 req/s** | 3,143 req/s | we win (~4.5×) |
| remote latency (WAN) | ≈ tie | ≈ tie | round-trip-bound; physics, not code |
| bulk upload (10 MB) | 686 MB/s | 1046 MB/s | curl wins — C vs JS on bulk AEAD |

For one-shot and concurrent traffic, bun-tls is faster: curl_cffi pays Python + cffi +
libcurl-handle setup on every request and is serialized by the GIL. Over the internet,
both are bounded by network round-trips and converge. Bulk upload throughput favours
curl's native crypto.

## How it compares

![comparison](assets/comparison.svg)

The clients that let you control a TLS fingerprint — `curl_cffi` (patched libcurl) and
`utls` (Go) — all ship a compiled artifact. The ones with nothing to install —
`fetch`/`undici`, `requests`/`httpx` — can't shape the ClientHello at all. bun-tls sits
in the gap: full JA3/JA4 control, browser presets, resumption and 0-RTT, with nothing to
compile. The trade-off it accepts for that is HTTP/1.1 only (no HTTP/2).

## Pros & cons

**Pros**

- Zero native dependencies — pure TypeScript on Bun.
- Byte-exact JA3 / JA3N / JA4 control; faithful Chrome 131 / Firefox 148 / dart:io presets.
- `fromJa3()` reproduces any fingerprint from a string.
- Keep-alive + TLS 1.3 session resumption + 0-RTT (RFC 8448-validated).
- Certificate verification on by default, with path-building to a bundled root store.
- Faster than curl_cffi for one-shot and concurrent requests; small, readable codebase.

**Cons**

- TLS 1.3 only (no 1.2) and HTTP/1.1 only (no HTTP/2). Browser presets therefore advertise
  ALPN `http/1.1` — the JA3 still matches, but JA4's ALPN byte and the real protocol are
  h1, and public CDNs that gate 0-RTT behind h2 give this client 1-RTT resumption instead.
- From-scratch TLS, not independently audited — review `src/tls/verify.ts` before trusting
  it on a security-critical path.
- No HelloRetryRequest handling; FFDHE and ML-KEM groups are advertised but not negotiated
  (key share is X25519, server falls back).
- WAN latency is round-trip-bound; it ties curl, it does not beat it there.
- Bulk upload throughput trails curl's native AEAD.

## Test

```bash
bun test/all.ts          # offline: crypto, chacha, resumption vs RFC vectors
bun test/all.ts --live   # + network: handshake, JA3/JA4 echo, POST, resumption
```

## Limitations

- TLS 1.3 + HTTP/1.1 only (see Cons).
- Cert path-building anchors at the earliest chain cert signed by a known root (handles
  legacy cross-signed roots like GlobalSign R1 / AAA Certificate Services); exotic
  cross-sign-only paths fail closed — use `verify: false` if known-safe.
- `tls.peet.ws` renders JA4's `_a` without zero-padding the cipher count; this follows the
  FoxIO spec (`03`), so the `_a` prefix can differ by a leading zero while `_b`/`_c` match.

## Security note

This is a from-scratch TLS implementation built for fingerprint control, not a hardened
general-purpose TLS library. Certificate verification is implemented and on by default,
but review `src/tls/verify.ts` before relying on it where correctness matters.

## License

MIT
