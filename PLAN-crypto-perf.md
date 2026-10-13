# Crypto performance plan

Scope: crypto only — AEAD record layer, handshake key exchange + key schedule, the
crypto inside certificate checks, QUIC packet protection. Socket/transport/HTTP belong
to other work; this plan says where crypto stops being the bottleneck.

Measured 2026-10-13 on Windows 11 (26200), i5-14450HX, Bun 1.4.2 (Bun is 1.4.3 now:
re-baseline before C1). Benchmark scripts were throwaway session files; recreate them
under `bench/crypto/` when C1 starts.

## Where we lose today (`bench/compare/out-optimized.md`)

| scenario | bun-tls | best other |
|---|---|---|
| new connection, latency / CPU | 4.63 ms / 2.18 ms | impers (node) 2.86 ms / 1.88 ms |
| upload 10 MiB | 244 MB/s, 1.87 ms CPU/MB | impers (bun) 978 MB/s; curl_cffi 0.67 ms CPU/MB |
| download 10 MiB | 398 MB/s, 2.89 ms CPU/MB | impers (node) 479 MB/s, 2.05 ms CPU/MB |
| throughput, 10 concurrent | 34k req/s, 44 µs CPU/req | go-utls 50.8k req/s (on 4.4 cores) |

## Findings

**1. AEAD per record (AES-128-GCM).** node:crypto builds a new Cipher for each record and
allocates the output. Windows CNG (`bcrypt.dll`, part of the OS) keeps one key handle per
traffic key and seals/opens in place through `bun:ffi`:

| record | node seal | node open | CNG seal | CNG open | WebCrypto, 1 at a time | WebCrypto, 16 in parallel |
|---|---|---|---|---|---|---|
| 64 B | 1152 ns | 1027 ns | 284 ns | 286 ns | 13510 ns | 2949 ns |
| 1 KiB | 1560 ns | 1316 ns | 496 ns | 442 ns | 17126 ns | 3178 ns |
| 16 KiB | 9272 ns (1.8 GB/s) | 4466 ns (3.7 GB/s) | 1685 ns (9.7 GB/s) | 1589 ns (10.3 GB/s) | 20115 ns | 8422 ns (1.9 GB/s) |

The CNG times include a memcpy that resets the buffer for the next in-place run. CNG output
is byte-identical to node:crypto (sizes 0–16383, in place, a tampered tag is rejected).

**2. ChaCha20-Poly1305.** CNG has it, and it is synchronous. Per record: 64 B takes
381 ns (pure TS: 1845 ns); 16 KiB runs at 514 MB/s (pure TS: 92 MB/s). Output is
byte-identical to `core/chacha.ts`. For bulk data, WebCrypto with parallel batches still
reaches about 1 GB/s (earlier session), so it stays competitive there.

**3. New connection, chrome persona, local, verify off: crypto ≈ 450 µs of 1459 µs CPU.**

| item | today |
|---|---|
| `buildClientHello` | 92 µs: 17× `crypto.randomInt` = 28.5, JA3+JA3N = 5.4, JA4 = 8.6, x25519 keygen = 15, `randomBytes` = 3.3, extension building ≈ 30 |
| second x25519 keygen (hybrid share) | 15 µs |
| ML-KEM-768 through WebCrypto | keygen 64 + decapsulation 34 µs of compute, but A/B in the real flow (chrome vs an x25519-only share) shows **+235 µs CPU, +0.24 ms wall**. The extra comes from async thread hops. |
| x25519 ECDH | 31 µs |
| key schedule | 66 µs, of which 44 µs is re-concatenating and re-hashing the whole transcript at 7 checkpoints. An incremental hash with `copy()` snapshots takes 7.7 µs. |
| handshake records | about 10 µs |

**4. CNG ML-KEM-768 is synchronous.** Keygen + export takes 79 µs and decapsulation takes
25 µs. The export blob is `MLKEMPUBLICBLOB` (12-byte header, then `"768\0"` in UTF-16, then
the 1184-byte key). Interop check: CNG decapsulation returns the same secret as a WebCrypto
encapsulation.

**5. Other CNG facts.** CNG also has X25519 (`ECDH` with `curve25519`), P-256/384, HKDF,
SHA-2, RSA and ECDSA. `bun.exe` does **not** export BoringSSL symbols, so there is no way to
borrow Bun's own BoringSSL.

**6. ⚠ CNG overwrites the buffer when a tag check fails.** It decrypts in place first and
then verifies. So in-place decryption is allowed only on the synchronous, in-order path.
Never use it in a speculative queue (the ChaCha path re-decrypts after a KeyUpdate).

**7. QUIC builds a new AEAD key object and a new AES-ECB header-protection cipher for every
packet.** This costs 2.65–3.14 µs of crypto per 1200-byte packet, about 400 MB/s.

## Decision needed

Today's design rule (PLAN.md) is "node:crypto only, no native `.dll`". C1, C2 and the CNG
part of C5 call Windows' own `bcrypt.dll` through `bun:ffi`. That means no download, no
addon, the OS's FIPS-validated SymCrypt, and automatic fallback to the current node path.
If the answer is no, only C3, C4 and the cache-only part of C5 apply, and the bulk and
per-record gains drop out.

## Phases (each phase: own commit, tsc + `bun test/all.ts` + `--live`, no AI attribution)

### C1 — Native AEAD + zero-allocation record layer (biggest win)
- NEW `src/core/cng.ts` (bun:ffi → bcrypt.dll):
  - Initialize lazily, once per thread (Workers too).
  - Open the alg handles: `AES` + `ChainingModeGCM`, `CHACHA20_POLY1305`, and AES-ECB for C5.
  - `cngAead(alg, key)` → `{ sealInPlace, openInPlace, destroy }`.
  - The auth-info struct (88 bytes, x64) points only at long-lived scratch buffers (nonce,
    5-byte AAD, tag). Per record, copy into them; no BigInt or other allocation per call.
  - Check bounds on every length before each FFI call.
  - Known-answer self-test against node:crypto at init. If it fails, or if
    `BUN_TLS_CRYPTO=node` is set, return null so the node path is used.
- `core/crypto.ts`:
  - `Aead` gains `sealInPlace?(nonce, aad, buf, off, len)` (tag written after the data)
    and `openInPlace?(nonce, aad, ct)` (returns a view).
  - `aesGcm()` returns the CNG-backed Aead when available.
  - Update the comment at L206.
- `core/chacha.ts`: sync `seal`/`open` use CNG (handshake and small records). Keep the
  WebCrypto async path for bulk unless CNG-sync measures ≥ P6 end to end. If it does,
  delete the async path and the `readAppAsync` queue (less code).
- `tls/record.ts` `AeadDir`:
  - Reuse one nonce buffer (keep a fresh one only for async).
  - `encrypt`/`encryptMany`: write the header, the plaintext and the type byte straight into
    `out`, then `sealInPlace`. This removes the `concat` and `sealParts` copies.
  - `decrypt`: `openInPlace` on `rec.fragment`. That buffer is ours: a chunk view or a fresh
    copy of a record that straddled two chunks. Bun never reuses socket buffers
    (`test/transport.test.ts`).
- `tls/handshake12.ts` `Dir12`: same provider.
- NEW `test/cng.test.ts` (skipped on non-Windows):
  - CNG vs the node / pure-TS oracle for every length 0..16383 (stepped), AAD lengths 0..13,
    both algorithms.
  - Tampered tag, ciphertext, AAD or nonce must throw.
  - Handle-leak check: 10k key create/destroy cycles with flat process handle count.
- Expected: per-record crypto 4×–5.5× cheaper, no allocation per record. Upload ~1.87 →
  ~1.3 ms CPU/MB. Download ~2.89 → ~1.5–2.0 ms CPU/MB. Small-request throughput about +8–10%.
- Upload wall time is **not** crypto-bound: CPU is busy only ~45% of the upload. Closing
  244 → 900 MB/s is transport's job.

### C2 — Key shares off the critical path + synchronous ML-KEM
- NEW `src/core/keypool.ts`:
  - `takeShare(group)` returns a pre-generated, single-use keypair (x25519, mlkem768,
    secp256r1/384). If the pool is empty, generate inline.
  - Refill one keypair per `setImmediate`, so it runs during network waits and delays a
    ServerHello by at most ~80 µs. Depth 2 by default (Session may raise it to its
    concurrency). TTL 30 s.
  - **Never** hand out the same key twice (forward secrecy; a reused key_share is a
    tracking handle).
- `cng.ts` ML-KEM-768:
  - keygen: GenerateKeyPair → `ParameterSetName`=`768` → Finalize → Export `MLKEMPUBLICBLOB`,
    then strip the 12+8-byte header.
  - decapsulation: `BCryptDecapsulate`.
  - Fallback: WebCrypto (as today).
- Callers that switch to the pool: `handshake.ts` hybrid prep (L194–199) and decapsulation
  (L250, sync), `clienthello.ts` `genShare`, `quic/connection.ts` L116, `handshake12.ts` L337.
- Fidelity check first: does real Firefox (NSS) reuse one X25519 key for both the hybrid and
  the standalone share? Verify with a capture. If yes, reuse it for the Firefox persona only
  (faster and truer). Chrome keeps the two keys distinct.
- Expected: about −320 µs of crypto on the critical path per new connection
  (≈ 450 → ≈ 125 µs) and ≈ −0.3 ms wall. Pool refill still costs ~110 µs CPU, but in idle
  time.

### C3 — Pure-TS trims (no native, can start now)
- `clienthello.ts` `shuffle`: one `randomBytes`, then unbiased rejection sampling. Replaces
  17× `randomInt`: 28.5 → ~1 µs. Keep the CSPRNG.
- JA3/JA3N/JA4 become lazy getters on `BuiltHello`/`TlsClient`; they are informational only.
  This takes 14 µs off the path before the ClientHello is written. Check consumers:
  `client.ts`, `session.ts`, tests.
- `handshake.ts` transcript:
  - Keep one `createHash(alg)`, created at ServerHello, with the ClientHello bytes buffered
    until then. HRR resets it to `message_hash`.
  - Take snapshots with `.copy().digest()`; replaces `th()` concat + re-hash.
  - `crypto.ts` gets a `deriveSecret` variant that takes the hash. Today 44 µs → 7.7 µs.
- `crypto.ts`: memoize the zero-PSK `early_secret` and its `derived` secret per hash, and
  cache the HKDF-Expand-Label info prefixes. Key schedule 66 → ~25 µs.

### C4 — Certificate path (verify on, remote)
- `verify.ts`: parse the leaf once per handshake. Today `verifyChain` and
  `verifyCertificateVerify` each parse it and import its key. Cache the leaf KeyObject next
  to the `chainCache` entry.
- Optional, with the http owner: a module-level TicketStore for one-shot `request()`, so a
  repeat host resumes and skips chain + CertificateVerify. This stays coherent with the
  Chrome fingerprint, because Chrome resumes too.

### C5 — QUIC packet protection
- `quic/packet.ts`: one Aead and one header-protection cipher per `PacketKeys`, cached on
  the keys object instead of rebuilt per packet. Header protection uses a CNG AES-ECB key
  handle, or one long-lived node ECB cipher (`update()` without padding is reusable).
- Expected: 2.65–3.14 → ~0.7 µs per packet with CNG.

### C6 — Linux provider (optional; GitHub users / a future VPS)
- `src/core/ossl.ts`: dlopen `libcrypto.so.3` (fall back to `.so.1.1`).
  - One `EVP_CIPHER_CTX` per key; per record, set the new IV with
    `EVP_*Init_ex(ctx, NULL, NULL, NULL, iv)`, update in place, read the tag through ctrl.
  - ChaCha works the same way. ML-KEM only with OpenSSL ≥ 3.5.
  - Same tests as C1.
- macOS: keep the node fallback.

**Order:** C3 now. Then C1 → C2 → C5 after the decision. C4 can run in parallel. C6 is
optional.

## Expected end state (estimates; each phase gate confirms)

| | today | after | best other today |
|---|---|---|---|
| crypto, critical path, new connection | ≈ 450 µs | ≈ 125 µs | (BoringSSL/Go generate keys inline) |
| download CPU/MB | 2.89 | ≈ 1.5–2.0 | 2.05 |
| upload CPU/MB | 1.87 | ≈ 1.3 | 0.67 (wall time is transport-bound) |
| per-record overhead | ~1.1 µs + 3 allocations | ~0.3 µs, 0 allocations | — |
| QUIC per packet | ~3 µs | ~0.7 µs | — |

How this beats the others:
- Bulk crypto reaches parity with BoringSSL/Go: SymCrypt with VAES runs at ~10 GB/s, and
  decryption is in place, as in BoringSSL.
- New connections do strictly less work on the critical path than the others: key shares
  are ready before connect, and ML-KEM has no thread hop.
- Per-record cost is the lowest of all, and CPU per request was already the best.

Wall-clock upload/download, and the rest of the new-connection gap, are transport (`connect`
was 14% of profile samples, the largest single native cost after ML-KEM).

## Guards
- Treat FFI as memory-unsafe: check bounds on every length. Struct pointers may refer only
  to long-lived scratch buffers. Run a fuzz oracle test against node:crypto.
- In-place decryption only in order and synchronously (finding 6). A decryption failure
  closes the connection, and the buffer is never handed out.
- Key handles: `BCryptDestroyKey` on AeadDir replacement (KeyUpdate) and on close, with a
  `FinalizationRegistry` as a backstop.
- Probe availability per algorithm. ChaCha and ML-KEM exist only on recent Windows 11, and
  each algorithm falls back on its own.
- Run tests twice in CI: the default provider and `BUN_TLS_CRYPTO=node`. `bun:ffi` is still
  marked experimental, so pin the Bun version.

## Not doing (measured dead ends)
- WebCrypto AES for records: a sequential op takes 13.5 µs (the async hop); tried before,
  throughput fell from 38.9k to 25k req/s.
- WASM AES: no AES-NI.
- Workers for small-request crypto: postMessage costs more than the crypto.
- `Bun.CryptoHasher` HMAC swap: 0.7 → 0.5 µs, only if the code is touched anyway.
- CNG X25519: not needed once keygen is pooled. ECDH stays at 31 µs on node; revisit only if
  the profile says so.

## Gate method
- Metric: CPU cycles per unit (`QueryProcessCycleTime`, all threads), plus wall, in
  interleaved A/B rounds (≥6), median.
- Wall-only numbers are unreliable on this laptop: the same configuration ranged
  2.1–6.1 ms across rounds.
- Fail a phase if 10-concurrent throughput or new-connection CPU regresses.
- Final: `bun bench/compare/run.ts 3` against `out-optimized.md`.
