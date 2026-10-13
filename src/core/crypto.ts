// TLS 1.3 crypto primitives via node:crypto (synchronous, full byte control).
// HKDF + Expand-Label + key schedule + AEAD (AES-GCM; ChaCha lives in chacha.ts
// if the server picks it). All validated against RFC 8448 vectors in test/.
import crypto from 'node:crypto';
import { concat } from './bytes';

export type HashAlg = 'sha256' | 'sha384';
export const hashLen = (h: HashAlg): number => (h === 'sha256' ? 32 : 48);
export const sha = (h: HashAlg, data: Uint8Array): Uint8Array => new Uint8Array(crypto.createHash(h).update(data).digest());
// Bun's native hasher: ~0.5 µs per small HMAC vs ~0.7 µs for node:crypto createHmac (a full
// handshake runs ~18 of them).
const hmac = (h: HashAlg, key: Uint8Array, data: Uint8Array): Uint8Array =>
	new Uint8Array(new Bun.CryptoHasher(h, key).update(data).digest());

export const hkdfExtract = (h: HashAlg, salt: Uint8Array, ikm: Uint8Array): Uint8Array => hmac(h, salt, ikm);

export function hkdfExpand(h: HashAlg, prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
	const hl = hashLen(h);
	const n = Math.ceil(length / hl);
	let t: Uint8Array = new Uint8Array(0);
	const out = new Uint8Array(n * hl);
	for (let i = 0; i < n; i++) {
		t = hmac(h, prk, concat(t, info, Uint8Array.of(i + 1)));
		out.set(t, i * hl);
	}
	return out.subarray(0, length);
}

const EMPTY = new Uint8Array(0);
const LABELS = new Map<string, Uint8Array>(); // "tls13 " + label, encoded once per (constant) label

/** HKDF-Expand-Label (RFC 8446 §7.1). Every TLS 1.3 / QUIC label asks for ≤ Hash.length bytes,
 *  which is ONE HMAC over HkdfLabel || 0x01 — built straight into a single buffer. */
export function expandLabel(h: HashAlg, secret: Uint8Array, label: string, context: Uint8Array, length: number): Uint8Array {
	let lab = LABELS.get(label);
	if (!lab) LABELS.set(label, (lab = new Uint8Array(Buffer.from('tls13 ' + label))));
	// HkdfLabel = uint16 length || opaque label<7..255> || opaque context<0..255>, then the counter
	const info = new Uint8Array(4 + lab.length + context.length + 1);
	info[0] = length >> 8;
	info[1] = length & 0xff;
	info[2] = lab.length;
	info.set(lab, 3);
	info[3 + lab.length] = context.length;
	info.set(context, 4 + lab.length);
	if (length > hashLen(h)) return hkdfExpand(h, secret, info.subarray(0, info.length - 1), length);
	info[info.length - 1] = 1;
	const t = hmac(h, secret, info);
	return length === t.length ? t : t.subarray(0, length);
}

/** Derive-Secret(secret, label, messages) — messages are hashed first. */
export const deriveSecret = (h: HashAlg, secret: Uint8Array, label: string, msgs: Uint8Array): Uint8Array =>
	expandLabel(h, secret, label, sha(h, msgs), hashLen(h));

// Per-hash constants of the schedule, computed once: Hash(""), and the 0-PSK early_secret +
// its "derived" secret (every full handshake starts from these).
const consts = new Map<HashAlg, { zero: Uint8Array; emptyHash: Uint8Array; early0: Uint8Array; derived0: Uint8Array }>();
function k(h: HashAlg) {
	let c = consts.get(h);
	if (!c) {
		const zero = new Uint8Array(hashLen(h));
		const emptyHash = sha(h, EMPTY);
		const early0 = hkdfExtract(h, zero, zero);
		consts.set(h, (c = { zero, emptyHash, early0, derived0: expandLabel(h, early0, 'derived', emptyHash, hashLen(h)) }));
	}
	return c;
}

// ── TLS 1.3 key schedule (RFC 8446 §7.1) ──────────────────────────────────────
// Functions below take Transcript-Hash values (the caller keeps a running hash), not messages.
export interface Schedule {
	h: HashAlg;
	handshake: Uint8Array;
	master: Uint8Array;
	cHs: Uint8Array;
	sHs: Uint8Array;
}

/** Stage 1: after we have the ECDHE shared secret + Transcript-Hash(CH..SH). `early` =
 *  a precomputed early_secret (from a resumption PSK); omitted → the 0-PSK one. */
export function deriveHandshake(h: HashAlg, ecdhe: Uint8Array, thCHSH: Uint8Array, early?: Uint8Array): Schedule {
	const c = k(h);
	const hl = hashLen(h);
	const derived = early ? expandLabel(h, early, 'derived', c.emptyHash, hl) : c.derived0;
	const handshake = hkdfExtract(h, derived, ecdhe);
	const cHs = expandLabel(h, handshake, 'c hs traffic', thCHSH, hl);
	const sHs = expandLabel(h, handshake, 's hs traffic', thCHSH, hl);
	const derived2 = expandLabel(h, handshake, 'derived', c.emptyHash, hl);
	const master = hkdfExtract(h, derived2, c.zero);
	return { h, handshake, master, cHs, sHs };
}

/** Stage 2: app traffic secrets, Transcript-Hash(CH..server Finished). */
export function appSecrets(s: Schedule, thToServerFin: Uint8Array): { cAp: Uint8Array; sAp: Uint8Array } {
	return {
		cAp: expandLabel(s.h, s.master, 'c ap traffic', thToServerFin, hashLen(s.h)),
		sAp: expandLabel(s.h, s.master, 's ap traffic', thToServerFin, hashLen(s.h))
	};
}

/** key + iv from a traffic secret. */
export function trafficKey(h: HashAlg, secret: Uint8Array, keyLen: number): { key: Uint8Array; iv: Uint8Array } {
	return {
		key: expandLabel(h, secret, 'key', EMPTY, keyLen),
		iv: expandLabel(h, secret, 'iv', EMPTY, 12)
	};
}

/** Finished verify_data = HMAC(finished_key, Transcript-Hash). */
export function finishedVerify(h: HashAlg, baseSecret: Uint8Array, thash: Uint8Array): Uint8Array {
	const fk = expandLabel(h, baseSecret, 'finished', EMPTY, hashLen(h));
	return hmac(h, fk, thash);
}

// ── Resumption + 0-RTT (RFC 8446 §4.6.1, §7.1) ────────────────────────────────
/** early_secret = HKDF-Extract(0, PSK). PSK omitted → the 0-PSK early secret. */
export function earlySecret(h: HashAlg, psk?: Uint8Array): Uint8Array {
	return psk ? hkdfExtract(h, k(h).zero, psk) : k(h).early0;
}
/** resumption_master_secret = Derive-Secret(master, "res master", CH..client Finished). */
export const resumptionMaster = (h: HashAlg, master: Uint8Array, thToClientFin: Uint8Array): Uint8Array =>
	expandLabel(h, master, 'res master', thToClientFin, hashLen(h));
/** A ticket's PSK = HKDF-Expand-Label(res master, "resumption", ticket_nonce). */
export const resumptionPsk = (h: HashAlg, resMaster: Uint8Array, nonce: Uint8Array): Uint8Array =>
	expandLabel(h, resMaster, 'resumption', nonce, hashLen(h));
/** binder_key = Derive-Secret(early_secret, "res binder", ""). */
export const binderKey = (h: HashAlg, early: Uint8Array): Uint8Array => expandLabel(h, early, 'res binder', k(h).emptyHash, hashLen(h));
/** PSK binder = HMAC(finished_key(binder_key), Transcript-Hash(truncated ClientHello)). */
export function pskBinder(h: HashAlg, bKey: Uint8Array, thTruncated: Uint8Array): Uint8Array {
	const fk = expandLabel(h, bKey, 'finished', EMPTY, hashLen(h));
	return hmac(h, fk, thTruncated);
}
/** client_early_traffic_secret = Derive-Secret(early_secret, "c e traffic", ClientHello). */
export const clientEarlyTraffic = (h: HashAlg, early: Uint8Array, thCH: Uint8Array): Uint8Array =>
	expandLabel(h, early, 'c e traffic', thCH, hashLen(h));

/** application_traffic_secret_N+1 = HKDF-Expand-Label(secret, "traffic upd", "", Hash.len)
 *  — the post-handshake KeyUpdate rotation (RFC 8446 §7.2). */
export const updateTraffic = (h: HashAlg, secret: Uint8Array): Uint8Array =>
	expandLabel(h, secret, 'traffic upd', EMPTY, hashLen(h));

// ── TLS 1.2 PRF (RFC 5246 §5) ─────────────────────────────────────────────────
/** P_hash(secret, seed) = HMAC(secret, A(1)+seed) | HMAC(secret, A(2)+seed) | …
 *  where A(0)=seed, A(i)=HMAC(secret, A(i-1)). The TLS 1.2 PRF is P_<suite hash>. */
export function prf12(hash: 'sha256' | 'sha384', secret: Uint8Array, label: string, seed: Uint8Array, len: number): Uint8Array {
	const labelSeed = concat(Buffer.from(label), seed);
	const out = new Uint8Array(len);
	let a = labelSeed; // A(0)
	for (let off = 0; off < len; ) {
		a = new Uint8Array(crypto.createHmac(hash, secret).update(a).digest()); // A(i)
		const frag = new Uint8Array(crypto.createHmac(hash, secret).update(concat(a, labelSeed)).digest());
		out.set(frag.subarray(0, Math.min(frag.length, len - off)), off);
		off += frag.length;
	}
	return out;
}

// ── ML-KEM-768 (FIPS 203) via WebCrypto, for the X25519MLKEM768 hybrid group ─────
const subtle = globalThis.crypto.subtle;
const MLKEM = { name: 'ML-KEM-768' } as const;

/** Generate an ML-KEM-768 keypair: the 1184-byte encapsulation key (to send) + the
 *  decapsulation key (kept to recover the shared secret from the server's ciphertext). */
export async function mlkem768Keypair(): Promise<{ ek: Uint8Array; priv: CryptoKey }> {
	const kp = (await subtle.generateKey(MLKEM, true, ['encapsulateBits', 'decapsulateBits'])) as CryptoKeyPair;
	const ek = new Uint8Array(await subtle.exportKey('raw-public' as 'raw', kp.publicKey));
	return { ek, priv: kp.privateKey };
}

/** Recover the 32-byte ML-KEM-768 shared secret from the server's 1088-byte ciphertext. */
export async function mlkem768Decapsulate(priv: CryptoKey, ciphertext: Uint8Array): Promise<Uint8Array> {
	// @ts-expect-error — decapsulateBits is newer than the lib.dom types
	return new Uint8Array(await subtle.decapsulateBits(MLKEM, priv, ciphertext));
}

// ── X25519 ────────────────────────────────────────────────────────────────────
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');

export function x25519Keypair(): { priv: crypto.KeyObject; pub: Uint8Array } {
	const { privateKey, publicKey } = crypto.generateKeyPairSync('x25519');
	const der = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
	return { priv: privateKey, pub: new Uint8Array(der.subarray(der.length - 32)) };
}

export function x25519Shared(priv: crypto.KeyObject, peerRaw32: Uint8Array): Uint8Array {
	const spki = Buffer.concat([X25519_SPKI_PREFIX, Buffer.from(peerRaw32)]);
	const peer = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
	return new Uint8Array(crypto.diffieHellman({ privateKey: priv, publicKey: peer }));
}

// ECDHE P-256/P-384: SPKI prefix captured at runtime (constant per curve), peer
// = uncompressed point (0x04||X||Y). diffieHellman returns the X coordinate = shared.
const EC_CURVE: Record<number, string> = { 0x0017: 'prime256v1', 0x0018: 'secp384r1' };
const ecPrefix = new Map<number, Buffer>();
export function ecdheShared(group: number, priv: crypto.KeyObject, peerRaw: Uint8Array): Uint8Array {
	if (group === 0x001d) return x25519Shared(priv, peerRaw);
	const curve = EC_CURVE[group];
	if (!curve) throw new Error(`unsupported ECDHE group ${group}`);
	let prefix = ecPrefix.get(group);
	if (!prefix) {
		const { publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: curve });
		const der = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
		prefix = der.subarray(0, der.length - peerRaw.length);
		ecPrefix.set(group, prefix);
	}
	const peer = crypto.createPublicKey({ key: Buffer.concat([prefix, Buffer.from(peerRaw)]), format: 'der', type: 'spki' });
	return new Uint8Array(crypto.diffieHellman({ privateKey: priv, publicKey: peer }));
}

// ── AEAD: AES-GCM (nonce = iv XOR seq). ChaCha in chacha.ts. ──────────────────
export type Aead = {
	seal: (nonce: Uint8Array, aad: Uint8Array, pt: Uint8Array) => Uint8Array;
	open: (nonce: Uint8Array, aad: Uint8Array, ct: Uint8Array) => Uint8Array;
	/** Optional fast path: encrypt `parts` (concatenated) straight into `out` at `off`,
	 *  ciphertext then tag, returning the new offset. Avoids building a joined input
	 *  and a separate output per record. */
	sealParts?: (nonce: Uint8Array, aad: Uint8Array, parts: Uint8Array[], out: Uint8Array, off: number) => number;
	/** Optional async path for ciphers with no fast synchronous implementation (ChaCha20 on
	 *  Bun, which exposes it only through async WebCrypto). When present, the bulk record
	 *  paths (writeAppStream, readApp) use it — sealing many records with Promise.all runs
	 *  them on the native crypto threads at ~100× the pure-TS speed. seal/open stay for the
	 *  small, latency-sensitive handshake records. Output/input identical to seal/open. */
	sealAsync?: (nonce: Uint8Array, aad: Uint8Array, pt: Uint8Array) => Promise<Uint8Array>;
	openAsync?: (nonce: Uint8Array, aad: Uint8Array, ct: Uint8Array) => Promise<Uint8Array>;
	keyLen: number;
};

const TAG16 = { authTagLength: 16 }; // reused per record instead of a fresh options object

export function aesGcm(keyLen: 16 | 32): (key: Uint8Array) => Aead {
	const algo = keyLen === 16 ? 'aes-128-gcm' : 'aes-256-gcm';
	return (raw: Uint8Array): Aead => {
		const key = crypto.createSecretKey(raw); // import once per traffic key, not per record
		// node:crypto AES-GCM stays SYNC: a WebCrypto async path was tried, but routing AES
		// through it made every small request pay async-dispatch overhead (tp 38.9k -> 25k) while
		// barely helping bulk download, since node's per-record Cipher is already ~1.8 GB/s.
		return {
			keyLen,
			seal(nonce, aad, pt) {
				const c = crypto.createCipheriv(algo, key, nonce, TAG16);
				c.setAAD(aad); // plaintextLength only matters for CCM/OCB, not GCM
				const body = c.update(pt); // GCM is a stream cipher: update() returns all ct
				c.final(); // empty for GCM, but required
				const out = new Uint8Array(body.length + 16);
				out.set(body);
				out.set(c.getAuthTag(), body.length);
				return out;
			},
			sealParts(nonce, aad, parts, out, off) {
				const c = crypto.createCipheriv(algo, key, nonce, TAG16);
				c.setAAD(aad);
				for (const p of parts) {
					const enc = c.update(p);
					out.set(enc, off);
					off += enc.length;
				}
				c.final();
				out.set(c.getAuthTag(), off);
				return off + 16;
			},
			open(nonce, aad, ct) {
				const tag = ct.subarray(ct.length - 16);
				const body = ct.subarray(0, ct.length - 16);
				const d = crypto.createDecipheriv(algo, key, nonce, TAG16); // length pin: a <16B ct gives a short tag → setAuthTag throws
				d.setAAD(aad);
				d.setAuthTag(tag);
				const out = d.update(body); // all plaintext; d.final() only verifies the tag
				d.final(); // throws on tag mismatch → we never return unverified plaintext
				// View, not a copy: d.update already returned a fresh Buffer for this record.
				return new Uint8Array(out.buffer, out.byteOffset, out.length);
			}
		};
	};
}

/** TLS 1.3 nonce: iv with the last 8 bytes XORed with seq (big-endian). */
export function aeadNonce(iv: Uint8Array, seq: bigint): Uint8Array {
	const n = new Uint8Array(iv);
	for (let i = 0; i < 8; i++) {
		n[11 - i] ^= Number((seq >> BigInt(8 * i)) & 0xffn);
	}
	return n;
}

/** Same nonce as aeadNonce, but from a Number sequence (no BigInt per record). Exact for
 *  seq < 2^53, far beyond any per-key record count. Only the low 32 bits land in bytes 8..11
 *  and the next 21 in bytes 4..7 — the IV's top 4 bytes are never touched (seq never reaches
 *  2^53), matching aeadNonce for every value a TLS connection can produce. */
export function seqNonce(iv: Uint8Array, seq: number): Uint8Array {
	const n = new Uint8Array(iv);
	const lo = seq >>> 0;
	const hi = Math.floor(seq / 0x100000000); // < 2^21
	n[11] ^= lo & 0xff;
	n[10] ^= (lo >>> 8) & 0xff;
	n[9] ^= (lo >>> 16) & 0xff;
	n[8] ^= (lo >>> 24) & 0xff;
	n[7] ^= hi & 0xff;
	n[6] ^= (hi >>> 8) & 0xff;
	n[5] ^= (hi >>> 16) & 0xff;
	return n;
}
