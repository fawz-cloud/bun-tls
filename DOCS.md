# bun-tls — documentation

Full reference for bun-tls: a TLS 1.3 / 1.2 HTTPS client written from scratch in
TypeScript on Bun, with control over the TLS fingerprint (JA3 / JA3N / JA4). For a short
intro see the [README](README.md); this file is the complete API.

**Contents**

- [Install](#install)
- [Quick start](#quick-start)
- [`request()`](#request)
- [`Session`](#session)
- [Fingerprints](#fingerprints)
- [JA3 / JA3N / JA4](#ja3--ja3n--ja4)
- [TLS features](#tls-features)
- [Certificate verification & OCSP](#certificate-verification--ocsp)
- [HTTP/2](#http2)
- [Proxies](#proxies)
- [Cookies](#cookies)
- [Compression](#compression)
- [Low-level API](#low-level-api)
- [Exports](#exports)
- [Architecture](#architecture)
- [Scope & caveats](#scope--caveats)
- [Testing](#testing)

---

## Install

```bash
bun add github:fawz-cloud/bun-tls   # or: git clone, then import from ./src
```

Requires Bun ≥ 1.1. No build step, no native addon — `node:crypto` (Bun's own OpenSSL)
supplies the primitives; every ClientHello byte is assembled in TypeScript.

```ts
import { request, Session, clients, fromJa3 } from './src';
```

---

## Quick start

```ts
import { request, Session, clients } from './src';

// one-shot (certificate verified by default)
const r = await request({ url: 'https://api.github.com/' });
console.log(r.status, r.json(), r.ja3, r.ja4);

// impersonate a browser fingerprint
await request({ url: 'https://example.com/', fingerprint: clients.chrome() });

// a session: cookies, redirects, keep-alive, resumption
const s = new Session();
await s.get('https://example.com/login');
await s.post('https://example.com/do', { body: 'x=1' });
s.close();
```

---

## `request()`

```ts
function request(options: RequestOptions): Promise<ClientResponse>;
```

One request over one fresh connection (`Connection: close`). For connection reuse use
[`Session`](#session).

### `RequestOptions`

| field | type | default | notes |
|---|---|---|---|
| `url` | `string` | — | **required**; must be `https:` |
| `method` | `string` | `'GET'` | any HTTP method |
| `headers` | `Record<string,string>` | see below | merged over the defaults |
| `body` | `string \| Uint8Array` | — | sets `Content-Length` |
| `fingerprint` | `Fingerprint` | `modern()` | see [Fingerprints](#fingerprints) |
| `persona` | `string \| Persona` | — | coherent browser identity (TLS + h2 + headers), see [Personas](#personas) |
| `verify` | `boolean` | `true` | `false` skips certificate verification (like curl `-k`) |
| `ocsp` | `'off' \| 'soft' \| 'hard'` | `'off'` | revocation check, see [OCSP](#certificate-verification--ocsp) |
| `tls12` | `boolean` | `false` | speak TLS 1.2 instead of 1.3 |
| `http2` | `boolean` | `false` | negotiate ALPN h2 (falls back to h1) |
| `proxy` | `string` | — | `http://…` or `socks5://…`, see [Proxies](#proxies) |
| `timeoutMs` | `number` | — | total timeout; closes the socket on expiry |

Default headers (each overridable via `headers`): `Host`, `User-Agent: bun-tls/0.1`,
`Accept: */*`, `Accept-Encoding: gzip, deflate, br, zstd`.

### `ClientResponse`

Extends `HttpResponse` with fingerprint echo fields.

| field | type | notes |
|---|---|---|
| `status` | `number` | |
| `statusText` | `string` | |
| `headers` | `Record<string, string \| string[]>` | repeated headers (e.g. `set-cookie`) become arrays |
| `body` | `Uint8Array` | decompressed |
| `text()` | `() => string` | body as UTF-8 |
| `json<T>()` | `() => T` | parsed body |
| `reusable` | `boolean` | framed body + no `Connection: close` |
| `ja3`, `ja3Hash` | `string` | JA3 of the ClientHello actually sent, + its MD5 |
| `ja3n`, `ja3nHash` | `string` | JA3 with extensions sorted (stable under `permute`) |
| `ja4` | `string` | JA4 |
| `alpn` | `string \| null` | negotiated ALPN (`h2`, `http/1.1`, …) |

The JA3/JA4 are computed by parsing the finished ClientHello, so "what we report" is
exactly "what we sent".

---

## `Session`

```ts
const s = new Session(options?: SessionOptions);
```

A cookie jar + redirect following + connection reuse + persistent defaults. This is the
fast path: subsequent requests to the same host skip the handshake.

### Methods

| method | notes |
|---|---|
| `get(url, opts?)` | `opts` is a partial `RequestOptions` |
| `post(url, opts?)` | |
| `request(req: RequestOptions)` | full control; redirects + cookies applied |
| `close()` | closes all pooled connections (keep-alive and HTTP/2) — call when done |
| `cookies` | the `CookieJar` (inspect/seed cookies) |

### `SessionOptions`

| field | type | default | notes |
|---|---|---|---|
| `fingerprint` | `Fingerprint` | `modern()` | |
| `persona` | `string \| Persona` | — | coherent browser identity, see [Personas](#personas) |
| `headers` | `Record<string,string>` | — | sent on every request |
| `proxy` | `string` | — | |
| `verify` | `boolean` | `true` | |
| `ocsp` | `'off' \| 'soft' \| 'hard'` | `'off'` | |
| `tls12` | `boolean` | `false` | |
| `http2` | `boolean` | `false` | keeps one multiplexed h2 connection per host |
| `keepAlive` | `boolean` | `true` | pool connections per `proxy\|host:port` |
| `maxRedirects` | `number` | `10` | `0` = don't follow |
| `zeroRtt` | `boolean` | `false` | opt into 0-RTT early data (see caveat) |
| `timeoutMs` | `number` | — | |

Per-request `RequestOptions` override the session defaults where both apply.

### What a Session reuses across requests

- **Keep-alive** (on): connections are pooled, so only the first request pays a handshake.
  A pooled connection the server has silently dropped is detected and retried on the next.
- **Session resumption** (on): `NewSessionTicket`s are cached and presented as a
  `pre_shared_key`, resuming in 1-RTT with no certificate exchange.
- **0-RTT early data** (`zeroRtt: true`, off by default): a GET/HEAD rides in the
  ClientHello, saving a round trip. **0-RTT is replayable** by a network attacker;
  restricting it to GET/HEAD does not remove the risk (whether a replay is harmless depends
  on the endpoint). Enable only where replay is safe. If the server declines, the request is
  resent over the completed handshake.

---

## Fingerprints

A `Fingerprint` is the JA3/JA4 control surface — it is *data*, never baked into the state
machine. There are three ways to get one.

### 1. Named client presets — `clients.*`

```ts
import { clients } from './src';
await request({ url, fingerprint: clients.chrome() });
```

| preset | source | notes |
|---|---|---|
| `clients.chrome` | utls `HelloChrome_131` spec | GREASE + permuted; JA3N `dee19b85…` |
| `clients.edge` | = `chrome` | Edge 131 is Chromium |
| `clients.firefox` | utls `HelloFirefox_148` spec | fixed order; JA3N `3d7d71e7…` |
| `clients.dart` | live capture (dart:io 3.13.3) | JA3 `9225d954…` |
| `clients.safari` | `fromJa3` rebuild | matches the reference JA3 only |
| `clients.okhttp` | `fromJa3` rebuild | matches the reference JA3 only |

Spec presets (`chrome`/`edge`/`firefox`/`dart`) reproduce the published JA3/JA3N of that
client version (verified against an echo server). `safari`/`okhttp` are rebuilt from a
reference JA3 string (`JA3.safari`, `JA3.okhttp`), so they match that JA3 and nothing more.

The raw `Fingerprint` presets are also exported directly: `modern`, `dart`, `chrome131`,
`firefox148`, `tls12`, and the map `presets`.

### 2. From a JA3 string — `fromJa3`

```ts
import { fromJa3 } from './src';
const fp = fromJa3('771,4865-4866-4867-49195-49199-…,0-23-65281-10-11-…,29-23-24,0', {
  grease: true,
});
await request({ url, fingerprint: fp });
```

```ts
function fromJa3(ja3: string, opts?: FromJa3Opts): Fingerprint;
```

| `FromJa3Opts` | type | default |
|---|---|---|
| `alpn` | `string[]` | `['http/1.1']` |
| `sigAlgs` | `number[]` | `DEFAULT_SIGALGS` |
| `keyShareGroups` | `number[]` | first supported JA3 curve |
| `grease` | `boolean` | `false` |

A JA3 omits ALPN, sigalgs and key-share contents, so pass those via `opts` when they
matter. `DEFAULT_SIGALGS` is exported for reference.

### 3. Custom — build the `Fingerprint`

```ts
import { ext, consts } from './src';

const fp: Fingerprint = {
  ciphers: [consts.Cipher.TLS_AES_128_GCM_SHA256, consts.Cipher.TLS_CHACHA20_POLY1305_SHA256],
  keyShareGroups: [consts.Group.x25519],
  extensions: [
    ext.serverName(),
    ext.supportedGroups([consts.Group.x25519, consts.Group.secp256r1]),
    ext.signatureAlgorithms([0x0403, 0x0804]),
    ext.supportedVersions(),
    ext.pskKeyExchangeModes([1]),
    ext.keyShare(),
    ext.alpn(['http/1.1']),
  ],
};
```

`Fingerprint` fields:

| field | type | notes |
|---|---|---|
| `ciphers` | `number[]` | wire order; GREASE values allowed (stripped from JA3) |
| `extensions` | `Extension[]` | **wire order = JA3/JA4 order** |
| `keyShareGroups` | `number[]` | groups a key_share is actually generated for |
| `compression` | `number[]?` | default `[0]` |
| `grease` | `boolean?` | inject GREASE like Chrome (hashes unchanged) |
| `permute` | `boolean?` | shuffle extension order each connection (Chrome behaviour) |

Extension builders (`import { ext } from './src'`), each `ext.<name>()`:

`serverName`, `supportedGroups(groups)`, `ecPointFormats(formats=[0])`,
`signatureAlgorithms(algs)`, `alpn(protocols)`, `supportedVersions(versions=[TLS13])`,
`pskKeyExchangeModes(modes=[1])`, `earlyData`, `cookie(data)`, `keyShare`,
`extendedMasterSecret`, `renegotiationInfo`, `sessionTicket`, `statusRequest`,
`compressCertificate(algos=[2])`, `signedCertTimestamp`, `recordSizeLimit(limit=0x4001)`,
`applicationSettings(protocols=['h2'], newCodepoint=false)`, `encryptedClientHelloGrease`,
`delegatedCredentials(algs)`, `grease(type, body?)`.

### 4. From a captured ClientHello — `fromClientHello`

```ts
import { fromClientHello } from './src';
// hex copied from Wireshark / tcpdump / a proxy (the handshake message or the TLS record)
const fp = fromClientHello('160301020001...');   // or a Uint8Array
await request({ url, fingerprint: fp });
```

Unlike `fromJa3` (which is lossy — a JA3 drops extension order and every extension body),
`fromClientHello` reproduces the capture **byte-for-byte**: the exact cipher list, extension
order, and each extension's raw bytes, so the JA3 / JA3N / JA4 match the capture exactly.
Capture a real client once, replay it forever. The inherently per-connection fields are
regenerated (as every real client also varies them): client random, session_id, and the
key_share public keys — none are in JA3/JA4. `server_name` is rewritten to the request's host,
and session-specific extensions (`pre_shared_key`, `early_data`) are dropped.

---

## Personas

A **persona** is one coherent browser identity across *every* fingerprinting layer at once:
the TLS ClientHello (JA3/JA4), the HTTP/2 (Akamai) fingerprint, **and** the HTTP header set +
order + User-Agent — all from one source. This is what sets bun-tls apart: anti-bot WAFs no
longer just check JA3, they check whether the layers *agree*. A Chrome JA3 sent with a
non-Chrome header order, or a `curl` User-Agent over a browser TLS fingerprint, is the exact
tell that catches most fingerprint-spoofing clients (curl_cffi included). A persona makes them
match.

```ts
import { request, Session } from './src';

await request({ url, persona: 'chrome' });          // TLS + h2 + headers + UA all Chrome 131
const s = new Session({ persona: 'firefox' });       // every request is coherent Firefox 148
```

| persona | TLS | h2 (Akamai) | headers / UA |
|---|---|---|---|
| `chrome` | Chrome 131 (permuted) | `…\|15663105\|0\|m,a,s,p` | Chrome order, `sec-ch-ua`, Chrome UA |
| `edge` | = Chrome 131 | = Chrome | Edge `sec-ch-ua` + UA |
| `firefox` | Firefox 148 | `…\|12517377\|0\|m,p,a,s` | Firefox order (no `sec-ch-ua`), Firefox UA |
| `safari` | Safari (JA3 rebuild) | `…\|10485760\|0\|m,s,p,a` | Safari order, Safari UA |

### Two properties that matter

- **Cross-layer coherence.** The TLS, h2 and HTTP layers all describe the *same* browser. Each
  persona ships the real header order and the real h2 fingerprint for that browser, not a
  one-size-fits-all default.
- **Per-connection JA3 rotation (anti-block-list).** Chrome and Edge permute their TLS
  extensions and rotate GREASE every connection — exactly as the real browsers do — so the
  **raw JA3 differs on every request** while the JA3N (the sorted "shape") stays a valid
  Chrome. There is no single JA3 string for a WAF to block-list. (Firefox/Safari keep a fixed
  order, matching the real clients.)

```ts
const a = await request({ url, persona: 'chrome' });
const b = await request({ url, persona: 'chrome' });
a.ja3Hash !== b.ja3Hash;   // true  — different raw JA3 each time
a.ja3nHash === b.ja3nHash;  // true  — both are Chrome 131
```

### API

- `request({ persona })` / `new Session({ persona })` — a name
  (`'chrome' | 'edge' | 'firefox' | 'safari'`) or a `Persona` object.
- An explicit `fingerprint`, `http2` or `headers` still overrides the persona's.
- `personas` — the registry (`personas.chrome()` → `Persona`).
- `randomPersona()` — a uniform random persona, for rotating identities across requests.
- `resolvePersona(name | persona)`, `personaHeaders(persona)` — helpers.

A `Persona` is `{ name, fingerprint(), http2, h2Profile, headers: [name, value][] }` — build
your own to pin a specific OS/version, or tweak a registry one.

---

## JA3 / JA3N / JA4

- **JA3** — MD5 of `version,ciphers,extensions,curves,pointFormats` (GREASE stripped).
  Sensitive to extension order.
- **JA3N** — JA3 with the extension list sorted. Stable when a client permutes its
  extensions each connection (Chrome `tls_permute_extensions`), which is why the spec
  presets assert on JA3N.
- **JA4** — FoxIO's fingerprint: `t<ver><sni><nCiphers><nExts><alpn>_<cipherHash>_<extSigHash>`.

Compute them from any ClientHello:

```ts
import { buildClientHello, ja3FromClientHello, ja4FromClientHello, clients } from './src';
const ch = buildClientHello(clients.chrome(), 'example.com');
ja3FromClientHello(ch.bytes); // { ja3, ja3Hash, ja3n, ja3nHash }
ja4FromClientHello(ch.bytes); // "t13d…_…_…"
```

**A matched JA3/JA4 is not a full client clone** — it summarises only part of the
ClientHello. See [Scope](#scope--caveats).

---

## TLS features

### Versions

- **TLS 1.3** (RFC 8446) by default. Full handshake, hand-written on a raw `Bun.connect`
  socket.
- **TLS 1.2** (RFC 5246) opt-in with `tls12: true` — ECDHE + AEAD only (AES-GCM,
  ChaCha20-Poly1305), extended master secret (RFC 7627), ServerKeyExchange-signature
  verification. No CBC, no static-RSA key exchange. Use the `tls12()` preset (default when
  `tls12: true` and no fingerprint is given), or any 1.2 fingerprint.

### Key exchange

X25519, P-256, P-384, and the post-quantum **X25519MLKEM768** hybrid (ML-KEM-768 via
WebCrypto) are all negotiable, including when the server asks for a group we only advertised
via **HelloRetryRequest**. The Chrome/Firefox presets send the ML-KEM share, so they reach
PQC-preferring CDNs (current Cloudflare/Google) with their real fingerprint. FFDHE groups
are advertised for fidelity but not implemented (no mainstream server requires them).

![handshake](assets/handshake.svg)

### Other handshake features (TLS 1.3)

- **Keep-alive**, **session resumption** (PSK) and opt-in **0-RTT** — see [Session](#session).
- **Post-handshake KeyUpdate** (RFC 8446 §7.2) — traffic keys rotate transparently.
- **Certificate compression** (RFC 8879) — zlib / brotli / zstd responses decompressed.
- **Optional mutual TLS** — a `CertificateRequest` is answered with an empty certificate, so
  optional-mTLS servers proceed (we hold no client cert).

The resumption / 0-RTT key schedule is checked byte-for-byte against the RFC 8448 §4
vectors; the TLS 1.2 PRF against a known test vector.

---

## Certificate verification & OCSP

Verification is **on by default** (`verify: true`). Three layers:

1. the leaf matches the hostname (DNS SAN, or IP SAN for an IP literal) and is in its
   validity window;
2. the chain links up (each cert signed by the next, signing certs constrained to CAs) to a
   trusted root — Bun's built-in roots ∪ the bundled `cacert.pem`, with path-building that
   anchors at the earliest chain cert a known root vouches for (covers legacy cross-signed
   roots such as GlobalSign R1 / AAA Certificate Services);
3. `CertificateVerify` (1.3) or the `ServerKeyExchange` signature (1.2) proves the server
   holds the leaf's private key (anti-MITM).

`verify: false` skips all of it (like curl `-k`). If verification fails on a host you trust,
add the missing root to `cacert.pem` rather than disabling verification.

### OCSP revocation — `ocsp`

Opt-in (`'off'` by default). RFC 6960; verifies the responder signature (by the issuer, or a
delegate the issuer signed carrying the OCSPSigning EKU), binds the response to the leaf via
CertID, and checks `thisUpdate`/`nextUpdate` freshness.

| mode | behaviour |
|---|---|
| `'off'` | no revocation check (default) |
| `'soft'` | browser-style: a confirmed `revoked` fails; a missing or `unknown` status is tolerated |
| `'hard'` | requires a good, in-date response — **stapled**, or **fetched** from the cert's AIA responder over HTTP |

`'hard'` fails on certs that carry no OCSP at all — including current Let's Encrypt (OCSP
retired 2025). There is no CRL fallback.

```ts
await request({ url, ocsp: 'soft' });               // browser-style
await request({ url, ocsp: 'hard' });               // require a good response
```

Lower-level OCSP helpers are exported: `verifyOcsp(der, leaf, issuer)` →
`'good' | 'revoked' | 'unknown'`, `fetchOcsp(leaf, issuer)`, `ocspUrl(leaf)`, and
`checkRevocation(certsDer, staple, mode)`.

---

## HTTP/2

```ts
await request({ url: 'https://nghttp2.org/', http2: true });   // one-shot, fresh conn
const s = new Session({ http2: true });                         // multiplexed
const [a, b] = await Promise.all([s.get(url1), s.get(url2)]);   // one connection
s.close();
```

- Negotiated via ALPN `h2`; falls back to HTTP/1.1 if the server declines.
- HPACK (static + dynamic table + Huffman), flow control, and the SETTINGS / WINDOW_UPDATE /
  pseudo-header order reproduce Chrome's h2 (Akamai) fingerprint
  `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`.
- `new Session({ http2: true })` keeps **one** h2 connection per host and multiplexes
  concurrent requests over it. The one-shot `request({ http2: true })` uses a fresh
  connection per call.

Low-level: `new H2Connection(tls)` (persistent, multiplexed), `h2Request(tls, req)`
(one-shot), and the `CHROME_H2` profile are exported.

---

## Proxies

```ts
await request({ url, proxy: 'http://user:pass@host:8080' });   // HTTP CONNECT tunnel
await request({ url, proxy: 'socks5://user:pass@host:1080' }); // SOCKS5 (RFC 1928/1929)
```

The proxy only tunnels bytes; the TLS handshake (and thus the fingerprint) is still ours,
end to end to the origin.

---

## Cookies

`Session` carries a `CookieJar` with real cookie semantics:

- domain (suffix) + path (prefix) matching;
- **Public Suffix List** guard — a `Domain=` attribute that is a public suffix (e.g.
  `.co.uk`) is rejected (supercookie protection);
- `__Host-` / `__Secure-` prefix rules (RFC 6265bis §5.5);
- `Secure`, `Max-Age` / `Expires`, `SameSite` (stored).

PSL helpers are exported standalone: `publicSuffix(host)`, `registrableDomain(host)`,
`isPublicSuffix(host)`.

```ts
const s = new Session();
s.cookies.setFromHeader('session=abc; Secure; Path=/', new URL('https://example.com/'));
```

---

## Compression

`Accept-Encoding: gzip, deflate, br, zstd` is sent by default and responses are decoded
automatically (via Bun's `zlib`). The decoded bytes are in `response.body`.

---

## Low-level API

The pieces `request`/`Session` are built from, for when you need the raw handshake.

### `openConnection(o: OpenOptions): Promise<TlsConn>`

Dial (TCP or proxy CONNECT) + TLS handshake → a ready connection. `OpenOptions`: `host`,
`port`, `proxy?`, `fingerprint?`, `verify?`, `ocsp?`, `tls12?`, `timeoutMs?`, and for TLS 1.3
`resume?`, `earlyData?`, `onTicket?`.

### `roundtrip(tls: TlsConn, o: RoundtripOptions, alreadySent?): Promise<ClientResponse>`

Send one request + read one response over an already-handshaked connection; does not close
it. `RoundtripOptions`: `method`, `host`, `path`, `headers`, `body?`, `keepAlive`.
`serializeForEarly(o)` turns one into the bytes to send as 0-RTT early data.

```ts
import { openConnection, roundtrip } from './src/http/client';

const tls = await openConnection({ host: 'example.com', port: 443 });
const res = await roundtrip(tls, { method: 'GET', host: 'example.com', path: '/', headers: {}, keepAlive: true });
console.log(res.status, tls.ja3Hash, tls.peerCertificates.length);
tls.close();
```

### `TlsConn`

The post-handshake surface shared by the TLS 1.3 (`TlsClient`) and 1.2 (`Tls12Client`)
clients: `writeApp(d)`, `writeAppStream(d)`, `readApp()`, `close()`, `alpn`,
`ja3`/`ja3Hash`/`ja3n`/`ja3nHash`/`ja4`, `resumed`, `earlyAccepted`, `peerCertificates`
(DER, leaf first), `ocspStaple`.

### Transport

`tcpConnect(host, port)`, `proxyConnect(proxyUrl, host, port)`, `socks5Connect(...)` all
return a `Transport` (raw byte stream). `withH2(fp)` returns a copy of a fingerprint whose
ALPN advertises `h2`.

---

## Exports

Everything below is re-exported from `./src` (`index.ts`):

| export | kind | what |
|---|---|---|
| `request` | fn | one-shot request |
| `Session`, `CookieJar` | class | stateful client + cookie jar |
| `clients`, `JA3` | const | named presets + reference JA3 strings |
| `personas`, `resolvePersona`, `randomPersona`, `personaHeaders` | const/fn | coherent browser personas |
| `presets`, `modern`, `dart`, `chrome131`, `firefox148`, `tls12` | fn | raw `Fingerprint` presets |
| `fromJa3`, `DEFAULT_SIGALGS` | fn/const | build a fingerprint from a JA3 |
| `fromClientHello` | fn | byte-exact replay from a captured ClientHello |
| `buildClientHello`, `ja3FromClientHello`, `ja4FromClientHello` | fn | assemble / inspect a ClientHello |
| `TlsClient`, `Tls12Client`, `TlsConn` | class/type | handshake state machines |
| `verifyOcsp`, `fetchOcsp`, `ocspUrl`, `checkRevocation` | fn | OCSP |
| `h2Request`, `H2Connection`, `CHROME_H2`, `FIREFOX_H2`, `SAFARI_H2` | fn/class/const | HTTP/2 + per-browser h2 profiles |
| `publicSuffix`, `registrableDomain`, `isPublicSuffix` | fn | Public Suffix List |
| `tcpConnect`, `proxyConnect`, `socks5Connect`, `Transport` | fn/type | transport |
| `ext` | namespace | extension builders |
| `consts` | namespace | IANA numbers (below) |

Types: `RequestOptions`, `ClientResponse`, `SessionOptions`, `Fingerprint`, `FromJa3Opts`,
`Persona`, `OcspMode`, `OcspStatus`, `H2Request`, `H2Profile`, `TlsConn`.

`consts` holds `ContentType`, `HandshakeType`, `Ext`, `Cipher`, `Cipher12`, `Group`,
`SigAlg`, `TLS12`, `TLS13`, `GREASE`, `isGrease`.

---

## Architecture

![architecture](assets/architecture.svg)

Four layers, imports pointing down only:

```
core/  bytes + crypto primitives (HKDF, key schedule, AES-GCM, ChaCha, ECDHE, PRF, ML-KEM, ASN.1)
  ↓
tls/   handshake (1.3 + 1.2), record layer, cert verification + OCSP, transport
  ↓
fp/    fingerprint presets + fromJa3
  ↓
http/  http1 + http2 + request() + Session
```

The fingerprint is data (`Fingerprint` + `Extension[]`); the extension array order is the
wire order and therefore the JA3/JA4. JA3/JA4 are computed by parsing the finished
ClientHello, so what is reported always equals what is sent.

| module | concern |
|---|---|
| `core/bytes.ts` | Reader / Writer / concat / hex |
| `core/consts.ts` | IANA numbers + GREASE |
| `core/crypto.ts` | HKDF, key schedule, AEAD, X25519, P-256/384, ML-KEM, TLS 1.2 PRF |
| `core/chacha.ts` | ChaCha20-Poly1305 (pure TS) |
| `tls/extensions.ts` | one builder per extension |
| `tls/clienthello.ts` | assemble CH + JA3/JA3N/JA4 + permute |
| `tls/record.ts` | TLS 1.3 record layer + AEAD direction |
| `tls/handshake.ts` | TLS 1.3 client state machine |
| `tls/handshake12.ts` | TLS 1.2 client (ECDHE + AEAD) |
| `tls/verify.ts` | cert chain + hostname + CertificateVerify + OCSP gate |
| `tls/asn1.ts` | minimal DER reader + encoder |
| `tls/ocsp.ts` | OCSP (RFC 6960) |
| `tls/transport.ts` | Bun.connect byte stream + HTTP/SOCKS5 proxy |
| `fp/fingerprints.ts` | presets |
| `fp/clients.ts` | named registry |
| `fp/ja3.ts` | `fromJa3` |
| `http/http1.ts` | HTTP/1.1 + gzip/deflate/br/zstd |
| `http/h2.ts` | HTTP/2 (frames + HPACK + flow control + multiplexing) |
| `http/psl.ts` | Public Suffix List |
| `http/client.ts` | `request()` + `openConnection` / `roundtrip` |
| `http/session.ts` | `Session` |

---

## Scope & caveats

- **A matched JA3/JA4 is not a full client clone.** The presets reproduce the JA3/JA3N of a
  client version (echo-verified), not every byte of its handshake. `fromJa3()` rebuilds from
  a JA3 string, so it matches that JA3 and nothing more.
- **From-scratch TLS, not audited.** Certificate verification is implemented and on by
  default, but review `src/tls/verify.ts` before relying on it where correctness matters.
- **FFDHE** and **OCSP for certs without OCSP** (e.g. current Let's Encrypt) are the known
  non-reachable cases; see the relevant sections above.

---

## Testing

```bash
bun test/all.ts          # offline: crypto, chacha, resumption vs RFC vectors, cookies
bun test/all.ts --live   # + network: handshake, JA3/JA4 echo, POST, resumption, h2, OCSP, TLS 1.2
```

Reproducible benchmarks are in `bench/` (see the README).
