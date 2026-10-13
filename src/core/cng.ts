// Windows CNG (bcrypt.dll, part of the OS) through bun:ffi: the native fast path for the
// record-layer AEADs. One key handle per traffic key keeps the key schedule (AES round keys +
// GHASH table, or the ChaCha key) for the key's whole life, and each record is ONE
// BCryptEncrypt/BCryptDecrypt call working in place — no Cipher object per record and no
// output allocation. Measured (i5-14450HX): AES-128-GCM 16 KiB seal 9.3 µs with node:crypto →
// 1.7 µs, a 64-byte record 1.15 → 0.28 µs; ChaCha20-Poly1305 64 B 1.8 µs (pure TS) → 0.38 µs.
//
// Not a dependency: bcrypt.dll ships with Windows. Everything here is null when unavailable —
// not Windows, an algorithm this Windows build lacks, a failed known-answer self-test — or
// when BUN_TLS_CRYPTO=node, and callers keep their node:crypto / pure-TS paths.
//
// FFI is memory-unsafe, so every length is bounds-checked before a call, and the parameter
// block only ever points at buffers that outlive the call.
import { dlopen, FFIType, ptr, type Pointer } from 'bun:ffi';
import nodeCrypto from 'node:crypto';
import type { Aead } from './crypto';

const STATUS_AUTH_TAG_MISMATCH = 0xc000a002;
const P = FFIType.ptr;
const U32 = FFIType.u32;

let lib: ReturnType<typeof open> | null | undefined; // undefined = not tried yet
function open() {
	return dlopen('bcrypt.dll', {
		BCryptOpenAlgorithmProvider: { args: [P, P, P, U32], returns: FFIType.i32 },
		BCryptSetProperty: { args: [P, P, P, U32, U32], returns: FFIType.i32 },
		BCryptGenerateSymmetricKey: { args: [P, P, P, U32, P, U32, U32], returns: FFIType.i32 },
		BCryptEncrypt: { args: [P, P, U32, P, P, U32, P, U32, P, U32], returns: FFIType.i32 },
		BCryptDecrypt: { args: [P, P, U32, P, P, U32, P, U32, P, U32], returns: FFIType.i32 },
		BCryptDestroyKey: { args: [P], returns: FFIType.i32 }
	}).symbols;
}
function bcrypt() {
	if (lib === undefined) {
		lib = null;
		if (process.platform === 'win32' && process.env.BUN_TLS_CRYPTO !== 'node') {
			try {
				lib = open();
			} catch {
				/* no bcrypt.dll → node paths */
			}
		}
	}
	return lib;
}

const wstr = (s: string): Uint8Array => new Uint8Array(Buffer.from(s + '\0', 'utf16le'));
const handleOut = new BigUint64Array(1);

/** Open a CNG algorithm provider (+ optional property), or null if this Windows lacks it. */
function provider(alg: string, prop?: [string, string]): Pointer | null {
	const B = bcrypt();
	if (!B) return null;
	if (B.BCryptOpenAlgorithmProvider(ptr(handleOut), wstr(alg), null, 0) !== 0) return null;
	const h = Number(handleOut[0]) as Pointer; // a user-space address: exact as a Number
	if (prop) {
		const v = wstr(prop[1]);
		if (B.BCryptSetProperty(h, wstr(prop[0]), v, v.length, 0) !== 0) return null;
	}
	return h;
}

// Key handles of AEADs nobody destroyed explicitly are released when the AEAD is collected.
const reaper = new FinalizationRegistry<Pointer>((hKey) => bcrypt()?.BCryptDestroyKey(hKey));

/** Write a pointer (a Number < 2^53) as a little-endian u64. */
function setPtr(dv: DataView, off: number, p: number): void {
	dv.setUint32(off, p >>> 0, true);
	dv.setUint32(off + 4, Math.floor(p / 0x100000000), true);
}

const AAD_SCRATCH = 64; // TLS 1.3 AAD = 5 bytes, TLS 1.2 = 13; longer (QUIC headers) are pointed at directly

/** AEAD factory over a CNG provider handle: seal/open allocate (the Aead contract), while
 *  sealInPlace/openInPlace are the zero-copy record-layer paths. */
function cngAead(hAlg: Pointer, keyLen: number, raw: Uint8Array): Aead {
	const B = bcrypt()!;
	if (raw.length !== keyLen) throw new Error(`AEAD key must be ${keyLen} bytes`);
	if (B.BCryptGenerateSymmetricKey(hAlg, ptr(handleOut), null, 0, raw, keyLen, 0) !== 0) throw new Error('BCryptGenerateSymmetricKey failed');
	const hKey = Number(handleOut[0]) as Pointer;
	// BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO (x64, 88 bytes), reused for every call. Nonce and AAD
	// are copied into scratch buffers with fixed addresses; the tag pointer is set per call to the
	// tag's place in the caller's record buffer, so it is written/read there with no copy.
	const info = new Uint8Array(88);
	const dv = new DataView(info.buffer);
	const nonceS = new Uint8Array(12);
	const aadS = new Uint8Array(AAD_SCRATCH);
	const res = new Uint32Array(1);
	const pAad = ptr(aadS);
	dv.setUint32(0, 88, true); // cbSize
	dv.setUint32(4, 1, true); // dwInfoVersion
	setPtr(dv, 8, ptr(nonceS));
	dv.setUint32(16, 12, true); // cbNonce
	dv.setUint32(48, 16, true); // cbTag
	let live = true;

	const call = (encrypt: boolean, nonce: Uint8Array, aad: Uint8Array, buf: Uint8Array, off: number, len: number): void => {
		if (!live) throw new Error('AEAD key already destroyed (connection closed)');
		if (nonce.length !== 12) throw new Error('AEAD nonce must be 12 bytes');
		if (!Number.isInteger(off) || !Number.isInteger(len) || off < 0 || len < 0 || off + len + 16 > buf.length) throw new RangeError('AEAD buffer bounds');
		nonceS.set(nonce);
		if (aad.length <= AAD_SCRATCH) {
			aadS.set(aad);
			setPtr(dv, 24, aad.length ? pAad : 0);
		} else setPtr(dv, 24, ptr(aad));
		dv.setUint32(32, aad.length, true);
		setPtr(dv, 40, ptr(buf, off + len)); // tag sits right after the data
		const p = ptr(buf, off);
		const st = (encrypt ? B.BCryptEncrypt : B.BCryptDecrypt)(hKey, p, len, info, null, 0, p, len, res, 0) >>> 0;
		if (st === STATUS_AUTH_TAG_MISMATCH) throw new Error('AEAD tag mismatch (bad record MAC)');
		if (st !== 0) throw new Error(`CNG ${encrypt ? 'encrypt' : 'decrypt'} failed: 0x${st.toString(16)}`);
	};

	const aead: Aead = {
		keyLen,
		sealInPlace: (nonce, aad, buf, off, len) => call(true, nonce, aad, buf, off, len),
		openInPlace(nonce, aad, ct) {
			if (ct.length < 16) throw new Error('AEAD ciphertext shorter than the tag');
			call(false, nonce, aad, ct, 0, ct.length - 16);
			return ct.subarray(0, ct.length - 16);
		},
		seal(nonce, aad, pt) {
			const out = new Uint8Array(pt.length + 16);
			out.set(pt);
			call(true, nonce, aad, out, 0, pt.length);
			return out;
		},
		open: (nonce, aad, ct) => aead.openInPlace!(nonce, aad, ct.slice()), // never touches the caller's bytes
		destroy() {
			if (!live) return;
			live = false;
			reaper.unregister(aead);
			B.BCryptDestroyKey(hKey);
		}
	};
	reaper.register(aead, hKey, aead);
	return aead;
}

const fromHex = (h: string) => new Uint8Array(Buffer.from(h, 'hex'));
const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;

/** Known-answer check run once per algorithm before CNG is trusted with any record: seal must
 *  equal the reference, open must recover the plaintext, a flipped tag bit must be rejected. */
function selfTest(mk: (k: Uint8Array) => Aead, key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, pt: Uint8Array, want: Uint8Array): boolean {
	try {
		const a = mk(key);
		const ct = a.seal(nonce, aad, pt);
		const ok = same(ct, want) && same(a.open(nonce, aad, ct), pt);
		const bad = ct.slice();
		bad[bad.length - 1]! ^= 1;
		let rejected = false;
		try {
			a.open(nonce, aad, bad);
		} catch {
			rejected = true;
		}
		a.destroy!();
		return ok && rejected;
	} catch {
		return false;
	}
}

let gcm: ((key: Uint8Array) => Aead) | null | undefined;
/** AES-GCM over CNG (key 16 or 32 bytes), or null → use node:crypto. Checked against
 *  node:crypto's own AES-GCM once, on first use. */
export function cngAesGcm(): ((key: Uint8Array) => Aead) | null {
	if (gcm !== undefined) return gcm;
	gcm = null;
	const h = provider('AES', ['ChainingMode', 'ChainingModeGCM']);
	if (h === null) return null;
	const mk = (k: Uint8Array) => cngAead(h, k.length, k);
	for (const kl of [16, 32]) {
		const key = nodeCrypto.randomBytes(kl);
		const nonce = nodeCrypto.randomBytes(12);
		const aad = nodeCrypto.randomBytes(5);
		const pt = nodeCrypto.randomBytes(37);
		const c = nodeCrypto.createCipheriv(kl === 16 ? 'aes-128-gcm' : 'aes-256-gcm', key, nonce, { authTagLength: 16 });
		c.setAAD(aad);
		const want = Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]);
		if (!selfTest(mk, new Uint8Array(key), new Uint8Array(nonce), new Uint8Array(aad), new Uint8Array(pt), new Uint8Array(want))) return null;
	}
	return (gcm = mk);
}

let ecb: ((key: Uint8Array) => (block: Uint8Array) => Uint8Array) | null | undefined;
/** Single-block AES-ECB over CNG (QUIC header protection: mask = AES-ECB(hp, sample)), one key
 *  handle per hp key; or null → node:crypto. Checked against node:crypto once, on first use. */
export function cngAesEcb(): ((key: Uint8Array) => (block: Uint8Array) => Uint8Array) | null {
	if (ecb !== undefined) return ecb;
	ecb = null;
	const h = provider('AES', ['ChainingMode', 'ChainingModeECB']);
	if (h === null) return null;
	const B = bcrypt()!;
	const res = new Uint32Array(1);
	const mk = (key: Uint8Array) => {
		if (key.length !== 16 && key.length !== 32) throw new Error('AES key must be 16 or 32 bytes');
		if (B.BCryptGenerateSymmetricKey(h, ptr(handleOut), null, 0, key, key.length, 0) !== 0) throw new Error('BCryptGenerateSymmetricKey failed');
		const hKey = Number(handleOut[0]) as Pointer;
		const encryptBlock = (block: Uint8Array): Uint8Array => {
			if (block.length < 16) throw new RangeError('AES block must be 16 bytes');
			const out = new Uint8Array(16);
			const st = B.BCryptEncrypt(hKey, block, 16, null, null, 0, out, 16, res, 0);
			if (st !== 0) throw new Error(`CNG AES-ECB failed: 0x${(st >>> 0).toString(16)}`);
			return out;
		};
		reaper.register(encryptBlock, hKey); // the handle lives as long as the function
		return encryptBlock;
	};
	try {
		for (const kl of [16, 32]) {
			const key = nodeCrypto.randomBytes(kl);
			const block = nodeCrypto.randomBytes(16);
			const c = nodeCrypto.createCipheriv(kl === 16 ? 'aes-128-ecb' : 'aes-256-ecb', key, null);
			c.setAutoPadding(false);
			if (!same(mk(new Uint8Array(key))(new Uint8Array(block)), new Uint8Array(c.update(block)))) return null;
		}
	} catch {
		return null;
	}
	return (ecb = mk);
}

// ── ML-KEM-768 (FIPS 203), synchronous: no async WebCrypto thread hop on the handshake path ──
// Loaded separately from the AEAD symbols: these exports exist only on recent Windows 11 builds,
// and a missing one must not take the AEADs down with it.
function openKem() {
	return dlopen('bcrypt.dll', {
		BCryptGenerateKeyPair: { args: [P, P, U32, U32], returns: FFIType.i32 },
		BCryptFinalizeKeyPair: { args: [P, U32], returns: FFIType.i32 },
		BCryptSetProperty: { args: [P, P, P, U32, U32], returns: FFIType.i32 },
		BCryptExportKey: { args: [P, P, P, P, U32, P, U32], returns: FFIType.i32 },
		BCryptDecapsulate: { args: [P, P, U32, P, U32, P, U32], returns: FFIType.i32 },
		BCryptDestroyKey: { args: [P], returns: FFIType.i32 }
	}).symbols;
}

/** An ML-KEM-768 key pair: the 1184-byte encapsulation key to send, and a one-shot
 *  decapsulation (the private key is destroyed once used). */
export interface KemKey {
	ek: Uint8Array;
	decapsulate(ct: Uint8Array): Uint8Array | Promise<Uint8Array>;
	/** Drop an unused key now (the server picked another group). */
	destroy?(): void;
}

let kem: (() => KemKey) | null | undefined;
/** ML-KEM-768 over CNG, or null → WebCrypto. Checked once: a key must export a 1184-byte
 *  encapsulation key and decapsulate a 1088-byte ciphertext to 32 bytes. (Interop with other
 *  implementations is covered by test/cng.test.ts against WebCrypto, and a wrong secret could
 *  only ever fail the handshake loudly — the Finished MACs would not match.) */
export function cngMlkem768(): (() => KemKey) | null {
	if (kem !== undefined) return kem;
	kem = null;
	const hAlg = provider('ML-KEM');
	if (hAlg === null) return null;
	let K: ReturnType<typeof openKem>;
	try {
		K = openKem();
	} catch {
		return null; // this Windows has the provider but not the KEM exports
	}
	const PS_NAME = wstr('ParameterSetName');
	const PS_768 = wstr('768');
	const BLOB = wstr('MLKEMPUBLICBLOB');
	const out = new Uint8Array(1300);
	const cb = new Uint32Array(1);
	const kemReaper = new FinalizationRegistry<Pointer>((h) => K.BCryptDestroyKey(h));
	const keypair = (): KemKey => {
		if (K.BCryptGenerateKeyPair(hAlg, ptr(handleOut), 0, 0) !== 0) throw new Error('ML-KEM keygen failed');
		const hKey = Number(handleOut[0]) as Pointer;
		let live = true;
		const destroy = () => {
			if (!live) return;
			live = false;
			kemReaper.unregister(k);
			K.BCryptDestroyKey(hKey);
		};
		const k: KemKey = { ek: new Uint8Array(0), decapsulate: () => new Uint8Array(0), destroy };
		kemReaper.register(k, hKey, k);
		if (K.BCryptSetProperty(hKey, PS_NAME, PS_768, PS_768.length, 0) !== 0 || K.BCryptFinalizeKeyPair(hKey, 0) !== 0) {
			destroy();
			throw new Error('ML-KEM-768 key setup failed');
		}
		// BCRYPT_MLKEM_KEY_BLOB: magic, cbParameterSet, cbKey, the parameter-set name, the key
		const st = K.BCryptExportKey(hKey, null, BLOB, out, out.length, cb, 0);
		const dv = new DataView(out.buffer);
		const cbPs = dv.getUint32(4, true);
		const cbKey = dv.getUint32(8, true);
		if (st !== 0 || cbKey !== 1184 || 12 + cbPs + cbKey !== cb[0]) {
			destroy();
			throw new Error('ML-KEM-768 export failed');
		}
		k.ek = out.slice(12 + cbPs, 12 + cbPs + cbKey);
		k.decapsulate = (ct) => {
			if (!live) throw new Error('ML-KEM key already used');
			if (ct.length !== 1088) throw new Error('ML-KEM-768 ciphertext must be 1088 bytes');
			const ss = new Uint8Array(32);
			const r = K.BCryptDecapsulate(hKey, ct, 1088, ss, 32, cb, 0);
			destroy(); // one-shot: the private key is gone either way
			if (r !== 0 || cb[0] !== 32) throw new Error('ML-KEM decapsulation failed');
			return ss;
		};
		return k;
	};
	try {
		const t = keypair();
		if (t.ek.length !== 1184 || (t.decapsulate(new Uint8Array(1088).fill(7)) as Uint8Array).length !== 32) return null;
	} catch {
		return null;
	}
	return (kem = keypair);
}

let chacha: ((key: Uint8Array) => Aead) | null | undefined;
/** ChaCha20-Poly1305 over CNG (newer Windows 11 builds), or null. Checked against the
 *  RFC 8439 §2.8.2 vector once, on first use. */
export function cngChaCha20Poly1305(): ((key: Uint8Array) => Aead) | null {
	if (chacha !== undefined) return chacha;
	chacha = null;
	const h = provider('CHACHA20_POLY1305');
	if (h === null) return null;
	const mk = (k: Uint8Array) => cngAead(h, 32, k);
	const pt = new Uint8Array(Buffer.from("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."));
	const want = fromHex(
		'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116' +
			'1ae10b594f09e26a7e902ecbd0600691'
	);
	const ok = selfTest(mk, fromHex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'), fromHex('070000004041424344454647'), fromHex('50515253c0c1c2c3c4c5c6c7'), pt, want);
	return (chacha = ok ? mk : null);
}
