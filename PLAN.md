# bun-tls — plan & status

Native Bun HTTPS client with a controllable TLS fingerprint (JA3/JA4), like
`curl_cffi` but with no Python/Dart/native `.dll`. Hand-written TLS 1.3 on a raw
`Bun.connect` socket, `node:crypto` only for primitives, so every ClientHello byte
is ours.

## Why

A Flutter/`dart:io` app's TLS fingerprint (BoringSSL) differs from
`fetch`/OpenSSL. Fingerprint-checking WAFs answer 200 to the real app and 405 to
OpenSSL clients. To match such a fingerprint you must control the exact
ClientHello — which no stock Node/Bun/Python HTTP API exposes. curl_cffi does it
via a patched libcurl (C); we do it in TS.

## Design rules (modular, long maintenance)

- One file = one concern, each small, each with a sibling test where vectors exist.
- The fingerprint is DATA (`Fingerprint` + `Extension[]`), never baked into the
  state machine. Extension array order = wire order = JA3/JA4.
- JA3/JA4 are computed by PARSING the finished ClientHello → "what we claim" always
  equals "what we send" (verified live against tls.peet.ws).

## Modules (`src/`, grouped by layer)

| file | concern |
|------|---------|
| `core/bytes.ts` | Reader/Writer/concat/hex |
| `core/consts.ts` | IANA numbers + GREASE |
| `core/crypto.ts` | HKDF, expand-label, key schedule, AES-GCM, X25519, P-256/384 ECDHE, nonce |
| `core/chacha.ts` | ChaCha20-Poly1305 (pure TS; Bun lacks it) |
| `tls/extensions.ts` | one builder per extension (order = JA3/JA4) |
| `tls/clienthello.ts` | assemble CH + compute JA3/JA3N + JA4; extension permute |
| `tls/record.ts` | record layer + AEAD direction (seq, nonce, inner type) |
| `tls/handshake.ts` | TLS 1.3 client state machine (verify on by default) |
| `tls/handshake12.ts` | TLS 1.2 client (ECDHE + AEAD), opt-in `tls12` |
| `tls/verify.ts` | cert chain (path-building) + hostname + CertificateVerify + OCSP gate |
| `tls/asn1.ts` | minimal DER reader + encoder (OCSP, cert fields) |
| `tls/ocsp.ts` | OCSP (RFC 6960): verify stapled/fetched response, CertID + signature + freshness |
| `tls/transport.ts` | Bun.connect byte stream + HTTP proxy CONNECT |
| `fp/fingerprints.ts` | presets (`modern`, `dart`, faithful `chrome131`, `firefox148`) |
| `fp/clients.ts` | named registry: `clients.{chrome,edge,firefox,dart,safari,okhttp}` |
| `fp/personas.ts` | coherent personas (TLS + h2 + header order + UA per browser) |
| `fp/ja3.ts` | `fromJa3(string)` → Fingerprint (impersonate from a JA3) |
| `fp/capture.ts` | `fromClientHello` — byte-exact replay from a captured ClientHello |
| `http/http1.ts` | HTTP/1.1 serialize/parse + gzip/deflate/br/zstd |
| `http/h2.ts` | HTTP/2: frames + HPACK + flow control + multiplexed `H2Connection` |
| `http/psl.ts` | Public Suffix List lookup (cookie supercookie guard) |
| `http/client.ts` | `request()` single-shot |
| `http/fetchlike.ts` | `fetch()` — Web-standard API, streaming Response body |
| `http/ws.ts` | WebSocket (RFC 6455) over the fingerprinted TLS |
| `quic/varint.ts` · `quic/crypto.ts` · `quic/packet.ts` | QUIC core: varints + RFC 9001 Initial packet protection (HTTP/3 foundation) |
| `http/session.ts` | `Session` = cookie jar + redirects + persistent opts |
| `index.ts` | public re-exports |
| `cacert.pem` | bundled Mozilla roots (union with Bun's) |

Layers: `core/` (bytes + crypto primitives) → `tls/` (handshake, records, cert verify, transport) → `fp/` (fingerprint presets + JA3) → `http/` (HTTP/1.1 + `request`/`Session`). Imports only point down the stack.

## Milestones

- [x] M0 crypto — RFC 8448 key schedule + X25519 + AES-GCM.
- [x] M1 ClientHello + JA3.
- [x] M2 record + handshake (server Finished verified, client Finished, app keys).
- [x] M3 live handshake — 200 vs example.com, cloudflare, api.github.com, postman-echo.
- [x] M4 JA3 echo exact; JA4 (b/c hashes match peet; _a is spec zero-padded).
- [x] M5 http1 — GET/POST, chunked/CL/EOF, gzip+deflate+br.
- [x] M6 proxy CONNECT (HTTP proxy + Basic auth).
- [x] M7 ChaCha20-Poly1305 (RFC 8439 vector + live vs cloudflare).
- [x] M8 cert verification (chain path-building, hostname SAN, CertificateVerify; verify:false to skip).
- [x] M9 P-256/P-384 ECDHE.
- [x] M10 Session: cookie jar + redirects; `fromJa3` impersonation.

**Phase 1 = curl_cffi parity: DONE.** Everything above is implemented and tested
(`bun test/all.ts --live` → 3/3).

### Faithful browser presets (2026-10-12)

- [x] JA3N (extensions sorted) computed alongside JA3; exposed on the response
      (`ja3n`, `ja3nHash`). Stable under extension permutation.
- [x] `permute` flag (Chrome `tls_permute_extensions`): shuffles the extension order
      each connection (crypto RNG). Raw JA3 then varies; JA3N stays stable.
- [x] `chrome`/`edge` = faithful **Chrome 131** (utls `HelloChrome_131`): MLKEM768 in
      supported_groups, GREASE ECH, brotli cert-compress, ALPS (old codepoint 17513),
      permuted. Live JA3N == `dee19b855b658c6aa0f575eda2525e19` (utls published value).
- [x] `firefox` = faithful **Firefox 148** (utls `HelloFirefox_148`): fixed ext order,
      no GREASE, MLKEM768 + P521 + FFDHE in groups, delegated_credentials,
      record_size_limit, zlib+brotli+zstd cert-compress, GREASE ECH. Live JA3N
      `3d7d71e7ee5cc9e08aa503d985e74b27`.
- [x] All verified live against `tls.peet.ws`: handshake 200, echo == our JA3/JA3N/JA4.
      (These servers chose X25519. If a server wants P-256/P-384 instead it sends a
      HelloRetryRequest and we retry with that share — handled + verified vs
      `openssl s_server -groups secp384r1`. Only MLKEM768/FFDHE, with no impl, are
      unreachable: "advertised" ≠ "negotiable".)

## Deliberately not done

- FFDHE key exchange (advertised for fingerprint fidelity, not implemented; no mainstream
  server requires it).
- CRL revocation (big delta lists; OCSP covers the same need per-cert).
- (done) Keep-alive, TLS session resumption (PSK), 0-RTT early data, HelloRetryRequest,
  X25519MLKEM768 post-quantum hybrid (ML-KEM via WebCrypto), RFC 8879 certificate
  decompression, post-handshake KeyUpdate, optional-mTLS (empty client Certificate),
  HTTP+SOCKS5 proxy, gzip/deflate/br/zstd, cookie Public Suffix List, HTTP/2 (HPACK + flow
  control + Chrome h2 fingerprint + Session multiplexing), OCSP revocation (RFC 6960:
  stapling + AIA fetch, own minimal DER codec in `tls/asn1.ts`), TLS 1.2 (opt-in `tls12`:
  ECDHE + AEAD AES-GCM/ChaCha20-Poly1305, extended master secret, ServerKeyExchange-signature
  verify; `tls/handshake12.ts`), coherent **personas** (`persona:` — one browser identity
  across TLS fingerprint + HTTP/2 Akamai profile + header order + User-Agent; per-connection
  JA3 rotation so no fixed JA3 to block-list; `fp/personas.ts`). Resumption/0-RTT key schedule validated vs RFC 8448 §4; the
  TLS 1.2 PRF vs a known test vector; cert verify enforces CA issuer + IP SANs; OCSP verifies the
  responder signature + CertID binding + freshness; failed handshakes close the socket.
- Cross-sign path building beyond "earliest chain cert signed by a known root" (covers
  GlobalSign R1 / AAA Certificate Services legacy tops; other paths fail verification —
  fix by adding the missing root to `cacert.pem`, not by disabling verification).

## Phase 2 (replace the Dart relay for Kopken)

- [x] Capture dart:io's real fingerprint (`capture.dart`, Dart 3.13.3 → tls.peet.ws,
      2026-10-12): `ja3_hash=9225d95490794840d9d5f1f94d339285`,
      `ja4=t13d1710_5b57614c22b0_78e6aca7449b`.
- [x] `presets.dart` reproduces it EXACTLY — verified live (JA3 hash + JA4 _b/_c
      match; JA4 _a differs only by peet's cosmetic no-zero-pad/omit-alpn rendering,
      wire bytes identical). Regression-checked in `test/live.test.ts`.
- [ ] Prove Kopken `/register` returns 200 (not 405) with `presets.dart` through a
      DataImpulse proxy. Needs real proxy creds + live Kopken — user-run.
- [ ] Wire into the panel behind a flag, keeping the Dart relay as fallback until
      the above is proven live.

## Test

```bash
bun scratch/bun-tls/test/all.ts          # offline (crypto, chacha)
bun scratch/bun-tls/test/all.ts --live   # + network
```
