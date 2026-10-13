// Assemble a ClientHello from a Fingerprint, and compute JA3/JA4 by PARSING the
// finished ClientHello (single source of truth: the hash == exactly what we send).
import crypto from 'node:crypto';
import { Reader, Writer, concat } from '../core/bytes';
import { Ext, GREASE, Group, TLS12, isGrease } from '../core/consts';
import { grease as greaseExt, pskKeyExchangeModes, earlyData, cookie as cookieExt, type Extension, type ExtCtx } from './extensions';
import { x25519Keypair, earlySecret, binderKey, pskBinder, sha } from '../core/crypto';
import type { Ticket } from './resumption';

const pickGrease = (not?: number | null): number => {
	let v: number;
	do {
		v = GREASE[Math.floor(Math.random() * GREASE.length)]!;
	} while (v === not);
	return v;
};

/** Fingerprint spec = the JA3/JA4 control surface. */
export interface Fingerprint {
	/** Cipher suites in wire order (GREASE values allowed; JA3 strips them). */
	ciphers: number[];
	/** Extensions in wire order (order = JA3/JA4). */
	extensions: Extension[];
	/** Groups we actually send a key_share for (usually [x25519]). */
	keyShareGroups: number[];
	/** compression_methods (TLS 1.3 requires [0]). */
	compression?: number[];
	/** Inject GREASE like Chrome (cipher[0], a leading+trailing GREASE ext, and
	 *  GREASE first in supported_groups/supported_versions/key_share). JA3/JA4
	 *  strip GREASE, so the hashes are unchanged; the wire layout follows Chrome's. */
	grease?: boolean;
	/** Shuffle extension order each connection (Chrome tls_permute_extensions).
	 *  Raw JA3 then varies per call (as with Chrome); JA3N (sorted) is stable. */
	permute?: boolean;
}

export interface BuiltHello {
	/** Full ClientHello handshake message (type + len + body). */
	bytes: Uint8Array;
	/** Private key per group for ECDHE once ServerHello arrives. */
	privs: Map<number, crypto.KeyObject>;
	random: Uint8Array;
	sessionId: Uint8Array;
	ja3: string;
	ja3Hash: string;
	/** JA3 with extensions sorted (GREASE-stripped). Stable under permute. */
	ja3n: string;
	ja3nHash: string;
	ja4: string;
	/** early_secret derived from the resumption PSK (only when `resume` was given). */
	earlySecret?: Uint8Array;
}

/** Resumption input for buildClientHello: present a ticket as pre_shared_key, and
 *  optionally advertise early_data (0-RTT). */
export interface ResumeSpec {
	ticket: Ticket;
	earlyData: boolean;
}

/** pre_shared_key extension with a ZEROED binder (patched after serialization, once
 *  the truncated-ClientHello transcript hash is known). One identity, one binder. */
function pskExtension(ticket: Ticket): Extension {
	const obfAge = (Date.now() - ticket.obtainedAt + ticket.ageAdd) >>> 0; // ms, mod 2^32
	const hLen = ticket.hash === 'sha256' ? 32 : 48;
	return {
		type: Ext.pre_shared_key,
		body: () =>
			new Writer()
				.block(2, (ids) => {
					ids.block(2, (e) => e.bytes(ticket.identity)); // identity (opaque<1..2^16-1>)
					ids.u32(obfAge); // obfuscated_ticket_age
				})
				.block(2, (bs) => bs.block(1, (b) => b.bytes(new Uint8Array(hLen)))) // one zeroed binder
				.build()
	};
}

/** Fisher-Yates shuffle from ONE crypto RNG draw (a randomInt per swap cost ~28 µs per
 *  ClientHello). `% (i + 1)` on a 32-bit draw is biased by < 2^-27 for any extension count —
 *  negligible for an extension-order permutation. */
function shuffle<T>(xs: T[]): T[] {
	const r = crypto.randomFillSync(new Uint32Array(xs.length));
	for (let i = xs.length - 1; i > 0; i--) {
		const j = r[i]! % (i + 1);
		[xs[i], xs[j]] = [xs[j]!, xs[i]!];
	}
	return xs;
}

function genShare(group: number): { priv: crypto.KeyObject; pub: Uint8Array } {
	if (group === Group.x25519) return x25519Keypair();
	if (group === Group.secp256r1 || group === Group.secp384r1) {
		const curve = group === Group.secp256r1 ? 'prime256v1' : 'secp384r1';
		const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: curve });
		const der = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
		const ptLen = group === Group.secp256r1 ? 65 : 97; // 0x04 + X + Y
		return { priv: privateKey, pub: new Uint8Array(der.subarray(der.length - ptLen)) };
	}
	throw new Error(`group ${group} not supported for key_share`);
}

/** After a HelloRetryRequest the second ClientHello must keep CH1's random + session_id
 *  (RFC 8446 §4.1.2), and its PSK binder is computed over the FULL retry transcript
 *  (synthetic message_hash(CH1) || HelloRetryRequest || truncated CH2), passed as `binderPrefix`. */
export interface RetrySpec {
	random: Uint8Array;
	sessionId: Uint8Array;
	binderPrefix: Uint8Array;
}

export function buildClientHello(fp: Fingerprint, host: string, resume?: ResumeSpec, cookie?: Uint8Array, prebuilt?: Map<number, Uint8Array>, retry?: RetrySpec): BuiltHello {
	const privs = new Map<number, crypto.KeyObject>();
	const shares = fp.keyShareGroups.map((group) => {
		const pre = prebuilt?.get(group);
		if (pre) return { group, pub: pre }; // caller supplied the public key (e.g. ML-KEM hybrid) and keeps its private part
		const { priv, pub } = genShare(group);
		privs.set(group, priv);
		return { group, pub };
	});
	const greaseA = fp.grease ? pickGrease() : null;
	const greaseB = fp.grease ? pickGrease(greaseA) : null;
	const ctx: ExtCtx = { host, shares, grease: greaseA };
	const rnd = retry ? null : new Uint8Array(crypto.randomBytes(64)); // random || session_id, one draw
	const random = retry?.random ?? rnd!.subarray(0, 32);
	const sessionId = retry?.sessionId ?? rnd!.subarray(32); // TLS1.3 middlebox-compat (kept across HRR)

	const ciphers = greaseA != null ? [greaseA, ...fp.ciphers] : fp.ciphers;
	// Resumption needs psk_key_exchange_modes present, plus early_data for 0-RTT. A
	// HelloRetryRequest cookie (if any) must be echoed in the second ClientHello.
	let base = fp.extensions;
	if (resume || cookie) {
		base = [...fp.extensions];
		if (cookie) base.push(cookieExt(cookie));
		if (resume) {
			if (!base.some((e) => e.type === Ext.psk_key_exchange_modes)) base.push(pskKeyExchangeModes([1]));
			if (resume.earlyData) base.push(earlyData());
		}
	}
	// Chrome permutes the extension order each connection (JA3N = sorted = stable).
	const mid = fp.permute ? shuffle([...base]) : base;
	// Chrome wraps the extension list in GREASE (leading + trailing, distinct values).
	let extensions = greaseA != null && greaseB != null ? [greaseExt(greaseA), ...mid, greaseExt(greaseB)] : [...mid];
	// pre_shared_key MUST be the last extension (RFC 8446 §4.2.11) — no trailing GREASE after it.
	if (resume) {
		extensions = greaseA != null ? [greaseExt(greaseA), ...mid] : [...mid];
		extensions.push(pskExtension(resume.ticket));
	}

	const body = new Writer()
		.u16(TLS12) // legacy_version
		.bytes(random)
		.block(1, (w) => w.bytes(sessionId))
		.block(2, (w) => ciphers.forEach((c) => w.u16(c)))
		.block(1, (w) => (fp.compression ?? [0]).forEach((c) => w.u8(c)))
		.block(2, (exts) => {
			for (const ext of extensions) {
				exts.u16(ext.type).block(2, (b) => b.bytes(ext.body(ctx)));
			}
		})
		.build();

	const bytes = new Writer()
		.u8(1) // handshake type client_hello
		.block(3, (w) => w.bytes(body))
		.build();

	let early: Uint8Array | undefined;
	if (resume) {
		// Patch the PSK binder: HMAC over the ClientHello transcript MINUS the binders
		// list (its last 3+hashLen bytes: 2-byte list len + 1-byte entry len + binder).
		const hLen = resume.ticket.hash === 'sha256' ? 32 : 48;
		early = earlySecret(resume.ticket.hash, resume.ticket.psk);
		// On a retry the binder transcript is (synthetic CH1 || HRR || truncated CH2).
		const truncated = concat(retry?.binderPrefix ?? new Uint8Array(0), bytes.subarray(0, bytes.length - (3 + hLen)));
		const binder = pskBinder(resume.ticket.hash, binderKey(resume.ticket.hash, early), sha(resume.ticket.hash, truncated));
		bytes.set(binder, bytes.length - hLen);
	}

	// JA3/JA4 are informational (parsed back out of `bytes`, ~14 µs): computed on first read, so
	// building and sending a ClientHello never waits on them.
	let j: ReturnType<typeof ja3FromClientHello> | undefined;
	let j4: string | undefined;
	const ja3s = () => (j ??= ja3FromClientHello(bytes));
	return {
		bytes,
		privs,
		random,
		sessionId,
		earlySecret: early,
		get ja3() { return ja3s().ja3; },
		get ja3Hash() { return ja3s().ja3Hash; },
		get ja3n() { return ja3s().ja3n; },
		get ja3nHash() { return ja3s().ja3nHash; },
		get ja4() { return (j4 ??= ja4FromClientHello(bytes)); }
	};
}

/** Parse a ClientHello (handshake msg) → JA3 + JA3N (sorted exts), each + MD5.
 *  Also a verification tool for fingerprints. */
export function ja3FromClientHello(hs: Uint8Array): { ja3: string; ja3Hash: string; ja3n: string; ja3nHash: string } {
	const r = new Reader(hs);
	if (r.u8() !== 1) throw new Error('not a ClientHello');
	const body = r.block(3);
	const legacyVersion = body.u16();
	body.bytes(32); // random
	body.block(1); // session_id
	const ciphers: number[] = [];
	const cr = body.block(2);
	while (cr.rem >= 2) ciphers.push(cr.u16());
	body.block(1); // compression
	const extTypes: number[] = [];
	const curves: number[] = [];
	const ecpf: number[] = [];
	const er = body.block(2);
	while (er.rem >= 4) {
		const t = er.u16();
		const eb = er.block(2);
		extTypes.push(t);
		if (t === Ext.supported_groups) {
			const g = eb.block(2);
			while (g.rem >= 2) curves.push(g.u16());
		} else if (t === Ext.ec_point_formats) {
			const f = eb.block(1);
			while (f.rem >= 1) ecpf.push(f.u8());
		}
	}
	const strip = (xs: number[]) => xs.filter((v) => !isGrease(v));
	const md5 = (s: string) => crypto.createHash('md5').update(s).digest('hex');
	const se = strip(extTypes);
	const tail = [strip(curves).join('-'), ecpf.join('-')];
	const cipherStr = strip(ciphers).join('-');
	const ja3 = [legacyVersion, cipherStr, se.join('-'), ...tail].join(',');
	// JA3N: same but extensions sorted ascending (stable when Chrome permutes).
	const ja3n = [legacyVersion, cipherStr, [...se].sort((a, b) => a - b).join('-'), ...tail].join(',');
	return { ja3, ja3Hash: md5(ja3), ja3n, ja3nHash: md5(ja3n) };
}

/** JA4 (FoxIO) for a TCP ClientHello. Needs supported_versions, ALPN, sigalgs,
 *  all parsed from the CH. Used for inspection / matching a target. */
export function ja4FromClientHello(hs: Uint8Array): string {
	const r = new Reader(hs);
	if (r.u8() !== 1) throw new Error('not a ClientHello');
	const body = r.block(3);
	body.u16(); // legacy_version
	body.bytes(32);
	body.block(1);
	const ciphers: number[] = [];
	const cr = body.block(2);
	while (cr.rem >= 2) ciphers.push(cr.u16());
	body.block(1);
	const extTypes: number[] = [];
	let sni = false;
	let alpnFirst = '';
	const sigAlgs: number[] = [];
	let maxVer = 0x0303;
	const er = body.block(2);
	while (er.rem >= 4) {
		const t = er.u16();
		const eb = er.block(2);
		extTypes.push(t);
		if (t === Ext.server_name) sni = true;
		else if (t === Ext.alpn) {
			const list = eb.block(2);
			alpnFirst = Buffer.from(list.block(1).buf).toString();
		} else if (t === Ext.signature_algorithms) {
			const g = eb.block(2);
			while (g.rem >= 2) sigAlgs.push(g.u16());
		} else if (t === Ext.supported_versions) {
			const g = eb.block(1);
			while (g.rem >= 2) {
				const v = g.u16();
				if (!isGrease(v)) maxVer = Math.max(maxVer, v); // ignore GREASE version
			}
		}
	}
	const strip = (xs: number[]) => xs.filter((v) => !isGrease(v));
	const pad2 = (n: number) => String(Math.min(n, 99)).padStart(2, '0');
	const ver = maxVer === 0x0304 ? '13' : maxVer === 0x0303 ? '12' : '11';
	const sc = strip(ciphers);
	const se = strip(extTypes);
	const alpnCode = alpnFirst ? alpnFirst[0]! + alpnFirst[alpnFirst.length - 1]! : '00';
	const a = `t${ver}${sni ? 'd' : 'i'}${pad2(sc.length)}${pad2(se.length)}${alpnCode}`;
	const hex4 = (n: number) => n.toString(16).padStart(4, '0');
	const sha12 = (s: string) => crypto.createHash('sha256').update(s).digest('hex').slice(0, 12);
	const b = sha12([...sc].sort((x, y) => x - y).map(hex4).join(','));
	// _c: extensions (sorted, EXCLUDING sni 0x0000 & alpn 0x0010) + "_" + sigalgs in original order.
	const extForC = se.filter((t) => t !== Ext.server_name && t !== Ext.alpn).sort((x, y) => x - y).map(hex4).join(',');
	const sig = strip(sigAlgs).map(hex4).join(',');
	const c = sha12(`${extForC}_${sig}`);
	return `${a}_${b}_${c}`;
}
