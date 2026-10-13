// TLS 1.2 client (RFC 5246 + RFC 5288/7905 AEAD + RFC 7627 extended master secret).
// ECDHE key exchange + AEAD ciphers only — no CBC, no static-RSA (both are either
// broken or a padding-oracle risk, and no modern server needs them). Opt-in via the
// `tls12` option; the default client stays TLS 1.3 (handshake.ts). The record layer,
// key schedule and Finished differ enough from 1.3 that this is its own state machine,
// but it reuses the ClientHello builder (so JA3 still works), cert-chain verification,
// OCSP and the AEAD primitives.
import { Reader, Writer, concat, hex } from '../core/bytes';
import { ContentType, HandshakeType, TLS12 } from '../core/consts';
import { Aead, aesGcm, prf12, sha, ecdheShared } from '../core/crypto';
import { takeEcShare } from '../core/keypool';
import { chacha20Poly1305 } from '../core/chacha';
import type { Fingerprint } from './clienthello';
import { buildClientHello } from './clienthello';
import { RecordReader, plaintextRecord } from './record';
import type { Transport } from './transport';
import { verifyChain, verifyOpts, checkRevocation, type OcspMode } from './verify';
import crypto from 'node:crypto';

interface Suite12 {
	aead: (key: Uint8Array) => Aead;
	keyLen: number;
	ivLen: 4 | 12; // GCM: 4-byte implicit IV + 8-byte explicit nonce; ChaCha: 12-byte fixed IV
	gcm: boolean;
	hash: 'sha256' | 'sha384'; // PRF + transcript hash
}
const SUITES: Record<number, Suite12> = {
	0xc02b: { aead: aesGcm(16), keyLen: 16, ivLen: 4, gcm: true, hash: 'sha256' },
	0xc02f: { aead: aesGcm(16), keyLen: 16, ivLen: 4, gcm: true, hash: 'sha256' },
	0xc02c: { aead: aesGcm(32), keyLen: 32, ivLen: 4, gcm: true, hash: 'sha384' },
	0xc030: { aead: aesGcm(32), keyLen: 32, ivLen: 4, gcm: true, hash: 'sha384' },
	0xcca9: { aead: chacha20Poly1305, keyLen: 32, ivLen: 12, gcm: false, hash: 'sha256' },
	0xcca8: { aead: chacha20Poly1305, keyLen: 32, ivLen: 12, gcm: false, hash: 'sha256' }
};

export interface Tls12Options {
	host: string;
	fingerprint: Fingerprint;
	verify?: boolean;
	ocsp?: OcspMode;
	onAlpn?: (proto: string | null) => void;
}

/** 8-byte big-endian. */
function u64(n: number): Uint8Array {
	const b = new Uint8Array(8);
	for (let i = 7; i >= 0; i--) {
		b[i] = n & 0xff;
		n = Math.floor(n / 256);
	}
	return b;
}

/** One AEAD direction for TLS 1.2 (seq + key/iv + suite layout). */
class Dir12 {
	seq = 0;
	constructor(
		private aead: Aead,
		private iv: Uint8Array,
		private suite: Suite12
	) {}
	private aad(type: number, ptLen: number): Uint8Array {
		return concat(u64(this.seq), Uint8Array.of(type, TLS12 >> 8, TLS12 & 0xff, (ptLen >> 8) & 0xff, ptLen & 0xff));
	}
	private nonce(explicit: Uint8Array): Uint8Array {
		if (this.suite.gcm) return concat(this.iv, explicit); // 4-byte IV || 8-byte explicit
		const n = Uint8Array.from(this.iv); // ChaCha: 12-byte IV XOR seq (RFC 7905)
		for (let i = 0; i < 8; i++) n[4 + i]! ^= explicit[i]!;
		return n;
	}
	seal(type: number, pt: Uint8Array): Uint8Array {
		const explicit = u64(this.seq);
		const aad = this.aad(type, pt.length);
		if (this.aead.sealInPlace) {
			// One buffer: header || [explicit nonce] || plaintext sealed in place || tag.
			const ex = this.suite.gcm ? 8 : 0;
			const len = ex + pt.length + 16;
			const out = new Uint8Array(5 + len);
			out.set([type, TLS12 >> 8, TLS12 & 0xff, (len >> 8) & 0xff, len & 0xff]);
			if (ex) out.set(explicit, 5);
			out.set(pt, 5 + ex);
			this.aead.sealInPlace(this.nonce(explicit), aad, out, 5 + ex, pt.length);
			this.seq++;
			return out;
		}
		const ct = this.aead.seal(this.nonce(explicit), aad, pt);
		this.seq++;
		return plaintextRecord(type, this.suite.gcm ? concat(explicit, ct) : ct);
	}
	open(type: number, fragment: Uint8Array): Uint8Array {
		const explicit = this.suite.gcm ? fragment.subarray(0, 8) : u64(this.seq);
		const body = this.suite.gcm ? fragment.subarray(8) : fragment;
		const aad = this.aad(type, body.length - 16);
		const nonce = this.nonce(explicit);
		// In place when native (the record is ours, opened once, in order — see AeadDir.decrypt).
		const pt = this.aead.openInPlace ? this.aead.openInPlace(nonce, aad, body) : this.aead.open(nonce, aad, body);
		this.seq++;
		return pt;
	}
	destroy(): void {
		this.aead.destroy?.();
	}
}

export class Tls12Client {
	private rr = new RecordReader();
	private hsbuf: Uint8Array = new Uint8Array(0);
	private transcript: Uint8Array[] = [];
	private suite!: Suite12;
	private write!: Dir12;
	private read!: Dir12;
	private appMode = false;
	alpn: string | null = null;
	ja3 = '';
	ja3Hash = '';
	ja3n = '';
	ja3nHash = '';
	ja4 = '';
	resumed = false;
	earlyAccepted = false;
	peerCertificates: Uint8Array[] = [];
	ocspStaple: Uint8Array | null = null;

	constructor(
		private t: Transport,
		private opts: Tls12Options
	) {}

	private async pullRecord() {
		for (;;) {
			const rec = this.rr.next();
			if (rec) return rec;
			const chunk = await this.t.read();
			if (chunk === null) return null;
			this.rr.feed(chunk);
		}
	}

	/** Next plaintext handshake message (reassembled across records). Used for the whole
	 *  server flight (pre-CCS) and for a plaintext NewSessionTicket after client Finished. */
	private async nextPlainMsg(): Promise<{ type: number; raw: Uint8Array; body: Reader } | null> {
		for (;;) {
			if (this.hsbuf.length >= 4) {
				const len = (this.hsbuf[1]! << 16) | (this.hsbuf[2]! << 8) | this.hsbuf[3]!;
				if (this.hsbuf.length >= 4 + len) {
					const raw = this.hsbuf.subarray(0, 4 + len);
					this.hsbuf = this.hsbuf.subarray(4 + len);
					return { type: raw[0]!, raw, body: new Reader(raw.subarray(4)) };
				}
			}
			const rec = await this.pullRecord();
			if (rec === null) return null;
			if (rec.type === ContentType.changeCipherSpec) continue;
			if (rec.type === ContentType.alert) throw new Error(`TLS alert level=${rec.fragment[0]} desc=${rec.fragment[1]}`);
			if (rec.type !== ContentType.handshake) continue;
			this.hsbuf = this.hsbuf.length ? concat(this.hsbuf, rec.fragment) : rec.fragment;
		}
	}

	private th(hash: 'sha256' | 'sha384'): Uint8Array {
		return sha(hash, concat(...this.transcript));
	}

	async handshake(): Promise<void> {
		// 1) ClientHello (reuse the builder; the tls12 preset carries no key_share /
		//    supported_versions, so the server negotiates TLS 1.2 from legacy_version).
		const ch = buildClientHello(this.opts.fingerprint, this.opts.host);
		const clientRandom = ch.random;
		this.transcript.push(ch.bytes);
		this.t.write(plaintextRecord(ContentType.handshake, ch.bytes));
		this.ja3 = ch.ja3; // computed while the server answers
		this.ja3Hash = ch.ja3Hash;
		this.ja3n = ch.ja3n;
		this.ja3nHash = ch.ja3nHash;
		this.ja4 = ch.ja4;

		// 2) Server flight: ServerHello, Certificate, [CertificateStatus], ServerKeyExchange,
		//    [CertificateRequest], ServerHelloDone.
		let serverRandom: Uint8Array | null = null;
		let ems = false;
		let ske: { group: number; pub: Uint8Array; params: Uint8Array; sigAlg: number; sig: Uint8Array } | null = null;
		let certReq = false;
		for (;;) {
			const msg = await this.nextPlainMsg();
			if (!msg) throw new Error('connection closed during TLS 1.2 handshake');
			this.transcript.push(msg.raw);
			if (msg.type === HandshakeType.serverHello) {
				const sh = parseServerHello12(msg.body);
				if (sh.version !== TLS12) throw new Error('server did not negotiate TLS 1.2 (version 0x' + sh.version.toString(16) + ')');
				this.suite = SUITES[sh.cipher] ?? (() => { throw new Error('server picked a non-AEAD/-ECDHE suite 0x' + sh.cipher.toString(16) + ' (unsupported)'); })();
				serverRandom = sh.random;
				ems = sh.ems;
				this.alpn = sh.alpn;
				this.opts.onAlpn?.(this.alpn);
			} else if (msg.type === HandshakeType.certificate) {
				this.peerCertificates = parseCertificate12(msg.body);
			} else if (msg.type === HandshakeType.certificateStatus) {
				if (msg.body.u8() === 1) this.ocspStaple = new Uint8Array(msg.body.block(3).buf); // stapled OCSP
			} else if (msg.type === HandshakeType.serverKeyExchange) {
				ske = parseServerKeyExchange(msg.body);
			} else if (msg.type === HandshakeType.certificateRequest) {
				certReq = true;
			} else if (msg.type === HandshakeType.serverHelloDone) {
				break;
			}
		}
		if (!serverRandom || !ske) throw new Error('TLS 1.2 handshake missing ServerHello or ServerKeyExchange');

		// 3) Verify the chain, then the ServerKeyExchange signature (server proves it holds
		//    the cert key, over client_random || server_random || ECDHE params — anti-MITM).
		if (this.opts.verify !== false) {
			const leafPub = verifyChain(this.peerCertificates, this.opts.host);
			const signed = concat(clientRandom, serverRandom, ske.params);
			const { hash, key } = verifyOpts(ske.sigAlg, leafPub);
			if (!crypto.verify(hash, Buffer.from(signed), key, Buffer.from(ske.sig)))
				throw new Error('ServerKeyExchange signature invalid (possible MITM)');
			await checkRevocation(this.peerCertificates, this.ocspStaple, this.opts.ocsp ?? 'off');
		}

		// 4) ECDHE: our key share for the server's group → premaster secret.
		if (ske.group !== 0x001d && ske.group !== 0x0017 && ske.group !== 0x0018) throw new Error('unsupported ECDHE group for TLS 1.2: ' + ske.group);
		const { priv, pub } = takeEcShare(ske.group); // pre-generated, single-use
		const pms = ecdheShared(ske.group, priv, ske.pub);

		// 5) Client Certificate (empty) if asked, then ClientKeyExchange — both plaintext,
		//    both part of the transcript, both before ChangeCipherSpec.
		if (certReq) {
			const emptyCert = new Writer()
				.u8(HandshakeType.certificate)
				.block(3, (w) => w.block(3, () => {})) // empty certificate_list
				.build();
			this.transcript.push(emptyCert);
			this.t.write(plaintextRecord(ContentType.handshake, emptyCert));
		}
		const cke = new Writer()
			.u8(HandshakeType.clientKeyExchange)
			.block(3, (w) => w.block(1, (p) => p.bytes(pub))) // ECDH public: 1-byte length + point
			.build();
		this.transcript.push(cke);
		this.t.write(plaintextRecord(ContentType.handshake, cke));

		// 6) Key schedule (RFC 5246 §8.1 + RFC 7627 EMS). The transcript hash through the
		//    ClientKeyExchange is both the EMS session_hash and the client-Finished input.
		const h = this.suite.hash;
		const handshakeHash = this.th(h);
		const master = ems
			? prf12(h, pms, 'extended master secret', handshakeHash, 48)
			: prf12(h, pms, 'master secret', concat(clientRandom, serverRandom), 48);
		const kl = this.suite.keyLen;
		const il = this.suite.ivLen;
		const kb = prf12(h, master, 'key expansion', concat(serverRandom, clientRandom), 2 * kl + 2 * il);
		const clientKey = kb.subarray(0, kl);
		const serverKey = kb.subarray(kl, 2 * kl);
		const clientIv = kb.subarray(2 * kl, 2 * kl + il);
		const serverIv = kb.subarray(2 * kl + il, 2 * kl + 2 * il);
		this.write = new Dir12(this.suite.aead(clientKey), clientIv, this.suite);
		this.read = new Dir12(this.suite.aead(serverKey), serverIv, this.suite);

		// 7) ChangeCipherSpec + encrypted client Finished (verify_data over the CH..CKE hash).
		this.t.write(plaintextRecord(ContentType.changeCipherSpec, Uint8Array.of(1)));
		const clientVerify = prf12(h, master, 'client finished', handshakeHash, 12);
		const finMsg = new Writer().u8(HandshakeType.finished).block(3, (w) => w.bytes(clientVerify)).build();
		this.transcript.push(finMsg);
		this.t.write(this.write.seal(ContentType.handshake, finMsg));

		// 8) Server flight 2: optional plaintext NewSessionTicket (counts toward the Finished
		//    hash), ChangeCipherSpec, then the encrypted server Finished.
		let ccsSeen = false;
		for (;;) {
			const rec = await this.pullRecord();
			if (rec === null) throw new Error('connection closed before server Finished');
			if (rec.type === ContentType.changeCipherSpec) {
				ccsSeen = true;
				continue;
			}
			if (rec.type === ContentType.alert) throw new Error(`TLS alert level=${rec.fragment[0]} desc=${rec.fragment[1]}`);
			if (rec.type !== ContentType.handshake) continue;
			if (!ccsSeen) {
				// plaintext NewSessionTicket (or other) before CCS — add to the transcript so
				// the server Finished hash matches; we don't use 1.2 resumption.
				this.hsbuf = this.hsbuf.length ? concat(this.hsbuf, rec.fragment) : rec.fragment;
				const nst = await this.takeBufferedMsg();
				if (nst) this.transcript.push(nst);
				continue;
			}
			const fin = this.read.open(ContentType.handshake, rec.fragment);
			const expect = prf12(h, master, 'server finished', this.th(h), 12);
			const fr = new Reader(fin);
			fr.u8(); // skip handshake type (finished)
			const got = new Uint8Array(fr.block(3).buf); // verify_data
			if (!timingEqual(expect, got)) throw new Error('server Finished mismatch (bad verify_data)');
			break;
		}
		this.appMode = true;
	}

	/** Pull one complete handshake message already sitting in hsbuf (no socket read). */
	private async takeBufferedMsg(): Promise<Uint8Array | null> {
		if (this.hsbuf.length < 4) return null;
		const len = (this.hsbuf[1]! << 16) | (this.hsbuf[2]! << 8) | this.hsbuf[3]!;
		if (this.hsbuf.length < 4 + len) return null;
		const raw = this.hsbuf.subarray(0, 4 + len);
		this.hsbuf = this.hsbuf.subarray(4 + len);
		return raw;
	}

	writeApp(data: Uint8Array): void {
		if (!this.appMode) throw new Error('handshake not finished');
		if (!data.length) return;
		const MAX = 16384; // TLSPlaintext max
		const parts: Uint8Array[] = [];
		for (let off = 0; off < data.length; off += MAX) parts.push(this.write.seal(ContentType.applicationData, data.subarray(off, off + MAX)));
		this.t.write(concat(...parts));
	}

	async writeAppStream(data: Uint8Array): Promise<void> {
		if (!this.appMode) throw new Error('handshake not finished');
		const MAX = 16384;
		const BATCH = MAX * 16;
		for (let off = 0; off < data.length; off += BATCH) {
			const end = Math.min(off + BATCH, data.length);
			const parts: Uint8Array[] = [];
			for (let p = off; p < end; p += MAX) parts.push(this.write.seal(ContentType.applicationData, data.subarray(p, Math.min(p + MAX, end))));
			await this.t.writeAsync(concat(...parts));
		}
	}

	async readApp(): Promise<Uint8Array | null> {
		if (!this.appMode) throw new Error('handshake not finished');
		for (;;) {
			const rec = await this.pullRecord();
			if (rec === null) return null;
			if (rec.type === ContentType.changeCipherSpec) continue;
			const pt = this.read.open(rec.type, rec.fragment);
			if (rec.type === ContentType.applicationData) return pt;
			if (rec.type === ContentType.alert) {
				if (pt[1] === 0) return null; // close_notify
				throw new Error('TLS alert desc=' + pt[1]);
			}
			// handshake (renegotiation / NewSessionTicket) after app data — ignore.
		}
	}

	close(): void {
		this.t.close();
		this.write?.destroy(); // native key handles go now, not at the next GC
		this.read?.destroy();
	}
}

function timingEqual(a: Uint8Array, b: Uint8Array): boolean {
	return a.length === b.length && crypto.timingSafeEqual(a, b);
}

interface ParsedSH12 {
	version: number;
	random: Uint8Array;
	cipher: number;
	ems: boolean;
	alpn: string | null;
}
function parseServerHello12(r: Reader): ParsedSH12 {
	const version = r.u16();
	const random = new Uint8Array(r.bytes(32));
	r.block(1); // session_id
	const cipher = r.u16();
	r.u8(); // compression
	let ems = false;
	let alpn: string | null = null;
	if (r.rem >= 2) {
		const exts = r.block(2);
		while (exts.rem >= 4) {
			const t = exts.u16();
			const eb = exts.block(2);
			if (t === 23) ems = true; // extended_master_secret
			else if (t === 16) {
				const list = eb.block(2);
				alpn = Buffer.from(list.block(1).buf).toString();
			}
		}
	}
	return { version, random, cipher, ems, alpn };
}

/** TLS 1.2 Certificate: list(block3 of cert(block3)). No per-cert extensions. */
function parseCertificate12(r: Reader): Uint8Array[] {
	const list = r.block(3);
	const certs: Uint8Array[] = [];
	while (list.rem >= 3) certs.push(new Uint8Array(list.block(3).buf));
	return certs;
}

/** ECDHE ServerKeyExchange: ECParameters (curve_type=named_curve, named_curve, point) +
 *  SignatureAndHashAlgorithm + signature. `params` = the exact signed ECDHE-params bytes. */
function parseServerKeyExchange(r: Reader): { group: number; pub: Uint8Array; params: Uint8Array; sigAlg: number; sig: Uint8Array } {
	const start = r.off;
	const curveType = r.u8();
	if (curveType !== 3) throw new Error('ServerKeyExchange is not named_curve ECDHE (curve_type ' + curveType + ')');
	const group = r.u16();
	const pub = new Uint8Array(r.block(1).buf);
	const params = new Uint8Array(r.buf.subarray(start, r.off)); // curve_type || named_curve || point
	const sigAlg = r.u16();
	const sig = new Uint8Array(r.block(2).buf);
	return { group, pub, params, sigAlg, sig };
}

// Self-check: PRF matches a known RFC 5246 test vector. Run: bun src/tls/handshake12.ts
if (import.meta.main) {
	// Vector from the TLS 1.2 PRF test (SHA-256) widely used (e.g. IETF mailing list):
	const secret = Buffer.from('9bbe436ba940f017b17652849a71db35', 'hex');
	const seed = Buffer.from('a0ba9f936cda311827a6f796ffd5198c', 'hex');
	const out = prf12('sha256', secret, 'test label', seed, 100);
	const expect = 'e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66';
	if (hex(out) !== expect) throw new Error('TLS 1.2 PRF self-check failed:\n got ' + hex(out) + '\n exp ' + expect);
	console.log('tls12 PRF ok');
}
