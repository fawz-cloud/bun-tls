// TLS 1.3 client state machine (RFC 8446), transport-agnostic.
// Flow: CH → SH → derive handshake keys → (ignore CCS) → EncryptedExtensions →
// [CertRequest?] → Certificate → CertVerify → server Finished (verified) →
// client Finished → app keys. Then writeApp/readApp use the app traffic keys.
// Certificate verification is on by default (verify.ts); pass verify:false to skip.
import { Reader, Writer, concat, hex } from '../core/bytes';
import { Cipher, ContentType, HandshakeType, Ext, Group } from '../core/consts';
import {
	Aead,
	aesGcm,
	appSecrets,
	deriveHandshake,
	finishedVerify,
	HashAlg,
	hashLen,
	sha,
	Schedule,
	trafficKey,
	ecdheShared,
	earlySecret,
	resumptionMaster,
	resumptionPsk,
	clientEarlyTraffic,
	updateTraffic,
	x25519Keypair,
	x25519Shared,
	mlkem768Keypair,
	mlkem768Decapsulate
} from '../core/crypto';
import { chacha20Poly1305 } from '../core/chacha';
import type { Fingerprint, ResumeSpec } from './clienthello';
import { buildClientHello } from './clienthello';
import { AeadDir, plaintextRecord, RecordReader } from './record';
import type { Transport } from './transport';
import type { Ticket } from './resumption';
import { verifyCertificateVerify, verifyChain, checkRevocation, type OcspMode } from './verify';
import crypto from 'node:crypto';
import zlib from 'node:zlib';

// Sentinel from routeApp meaning "record handled, keep reading" (vs. app bytes or null = EOF).
const CONTINUE: unique symbol = Symbol('continue');

interface Suite {
	hash: HashAlg;
	aead: (key: Uint8Array) => Aead;
	keyLen: number;
}
const SUITES: Record<number, Suite> = {
	[Cipher.TLS_AES_128_GCM_SHA256]: { hash: 'sha256', aead: aesGcm(16), keyLen: 16 },
	[Cipher.TLS_AES_256_GCM_SHA384]: { hash: 'sha384', aead: aesGcm(32), keyLen: 32 },
	[Cipher.TLS_CHACHA20_POLY1305_SHA256]: { hash: 'sha256', aead: chacha20Poly1305, keyLen: 32 }
};

/** HelloRetryRequest reuses this fixed SH.random (RFC 8446 §4.1.3). */
const HRR_RANDOM = 'cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c';

export interface TlsOptions {
	host: string;
	fingerprint: Fingerprint;
	/** Verify the server certificate (default true). false = skip (like curl verify=False). */
	verify?: boolean;
	/** OCSP revocation check (default 'off'): 'soft' tolerates a missing/unknown status like
	 *  browsers, 'hard' requires a good stapled-or-fetched response; 'revoked' always fails. */
	ocsp?: OcspMode;
	/** Negotiated ALPN read from EncryptedExtensions (informational). */
	onAlpn?: (proto: string | null) => void;
	/** Resume from a stored ticket (pre_shared_key). Enables 0-RTT if resume.earlyData. */
	resume?: ResumeSpec;
	/** Request bytes to send as 0-RTT early data (only used when resume.earlyData). */
	earlyData?: Uint8Array;
	/** Called for each NewSessionTicket the server sends (store for later resumption). */
	onTicket?: (t: Ticket) => void;
}

/** The post-handshake surface shared by the TLS 1.3 (TlsClient) and 1.2 (Tls12Client)
 *  clients — what http/client.ts, Session and H2Connection actually use. */
export interface TlsConn {
	writeApp(d: Uint8Array): void;
	writeAppStream(d: Uint8Array): Promise<void>;
	readApp(): Promise<Uint8Array | null>;
	close(): void;
	alpn: string | null;
	ja3: string;
	ja3Hash: string;
	ja3n: string;
	ja3nHash: string;
	ja4: string;
	resumed: boolean;
	earlyAccepted: boolean;
	peerCertificates: Uint8Array[];
	ocspStaple: Uint8Array | null;
}

export class TlsClient {
	private rr = new RecordReader();
	private hsbuf: Uint8Array = new Uint8Array(0); // handshake message reassembly
	// Transcript: messages are kept only until ServerHello fixes the hash; from then on one
	// running hash absorbs each message once and th() snapshots it (no re-hash of the whole
	// transcript at every checkpoint).
	private transcript: Uint8Array[] = [];
	private thash: crypto.Hash | null = null;
	private suite!: Suite;
	private sched!: Schedule;
	private readDir!: AeadDir; // server→client (active once keys exist)
	private writeDir: AeadDir | null = null; // client→server, encrypted
	private appRead!: AeadDir;
	private appWrite!: AeadDir;
	private appMode = false;
	// current application_traffic_secret per direction, for KeyUpdate rotation
	private sApSecret!: Uint8Array;
	private cApSecret!: Uint8Array;
	// Resumption master secret + its suite, for deriving PSKs from NewSessionTickets.
	private resMaster: Uint8Array | null = null;
	private resHash: HashAlg = 'sha256';
	private resCipher = 0;
	alpn: string | null = null;
	ja3 = '';
	ja3Hash = '';
	ja3n = '';
	ja3nHash = '';
	ja4 = '';
	/** Server certificate chain (DER), leaf first. Empty on a resumed handshake. */
	peerCertificates: Uint8Array[] = [];
	/** Stapled OCSP response (DER) from the leaf CertificateEntry, or null. */
	ocspStaple: Uint8Array | null = null;
	/** Server accepted our pre_shared_key (resumed handshake). */
	resumed = false;
	/** Server accepted our 0-RTT early data (the request was delivered in the CH flight). */
	earlyAccepted = false;

	constructor(
		private t: Transport,
		private opts: TlsOptions
	) {}

	/** In-flight record decrypts for the native-AEAD download path (ChaCha), oldest first. */
	private inflight: { rec: { type: number; fragment: Uint8Array }; dir: AeadDir; p: Promise<{ innerType: number; content: Uint8Array }> }[] = [];

	private async pullRecord() {
		for (;;) {
			const rec = this.rr.next();
			if (rec) return rec;
			const chunk = await this.t.read();
			if (chunk === null) return null;
			this.rr.feed(chunk);
		}
	}

	/** Get the NEXT handshake message (reassembled across records).
	 *  `encrypted` = decrypt with readDir first. CCS (type 20) is ignored. */
	private async nextHandshakeMsg(encrypted: boolean): Promise<{ type: number; raw: Uint8Array; body: Reader } | null> {
		for (;;) {
			// Enough bytes for one message? (type + u24 len + body)
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
			if (rec.type === ContentType.changeCipherSpec) continue; // middlebox compat
			if (rec.type === ContentType.alert) {
				const a = encrypted ? this.readDir.decrypt(rec).content : rec.fragment;
				throw new Error(`TLS alert level=${a[0]} desc=${a[1]}`);
			}
			let data: Uint8Array;
			if (encrypted) {
				const d = this.readDir.decrypt(rec);
				if (d.innerType !== ContentType.handshake) {
					if (d.innerType === ContentType.alert) throw new Error(`TLS alert desc=${d.content[1]}`);
					continue; // app data not expected during handshake
				}
				data = d.content;
			} else {
				if (rec.type !== ContentType.handshake) continue;
				data = rec.fragment;
			}
			this.hsbuf = this.hsbuf.length ? concat(this.hsbuf, data) : data;
		}
	}

	private addTranscript(raw: Uint8Array) {
		if (this.thash) this.thash.update(raw);
		else this.transcript.push(raw);
	}
	/** Transcript-Hash of every message so far (the running hash continues). */
	private th(): Uint8Array {
		return new Uint8Array(this.thash!.copy().digest());
	}

	async handshake(): Promise<void> {
		const resume = this.opts.resume;
		// X25519MLKEM768 hybrid: ML-KEM keygen is async, so build the key_share up front
		// (ek || X25519 pubkey) and keep both private parts for the shared-secret recovery.
		let hybrid: { x: crypto.KeyObject; mlkem: CryptoKey } | null = null;
		let prebuilt: Map<number, Uint8Array> | undefined;
		if (this.opts.fingerprint.keyShareGroups.includes(Group.x25519mlkem768)) {
			const x = x25519Keypair();
			const mk = await mlkem768Keypair();
			hybrid = { x: x.priv, mlkem: mk.priv };
			prebuilt = new Map([[Group.x25519mlkem768, concat(mk.ek, x.pub)]]);
		}
		// 1) ClientHello (+ pre_shared_key + early_data when resuming)
		let ch = buildClientHello(this.opts.fingerprint, this.opts.host, resume, undefined, prebuilt);
		this.addTranscript(ch.bytes);
		this.t.write(plaintextRecord(ContentType.handshake, ch.bytes));

		// 1b) 0-RTT: send the request as early application_data (client_early_traffic
		// keys) right after the ClientHello, before ServerHello arrives.
		let sentEarly = false;
		let earlyWrite: AeadDir | null = null; // client_early_traffic AEAD (also signs EndOfEarlyData)
		if (resume?.earlyData && ch.earlySecret && this.opts.earlyData?.length) {
			const t = resume.ticket;
			const suite = SUITES[t.cipher];
			if (suite && this.opts.earlyData.length <= t.maxEarlyData) {
				const cet = clientEarlyTraffic(suite.hash, ch.earlySecret, sha(suite.hash, ch.bytes));
				const k = trafficKey(suite.hash, cet, suite.keyLen);
				earlyWrite = new AeadDir(suite.aead(k.key), k.iv);
				this.t.write(earlyWrite.encryptMany(ContentType.applicationData, this.opts.earlyData, 16384 - 1));
				sentEarly = true;
			}
		}

		// The ClientHello is on the wire: compute its fingerprints while the server answers.
		this.ja3 = ch.ja3;
		this.ja3Hash = ch.ja3Hash;
		this.ja3n = ch.ja3n;
		this.ja3nHash = ch.ja3nHash;
		this.ja4 = ch.ja4;

		// 2) ServerHello — may be a HelloRetryRequest asking for a different key-share group.
		let sh = await this.nextHandshakeMsg(false);
		if (!sh || sh.type !== HandshakeType.serverHello) throw new Error('expected ServerHello, got type ' + sh?.type);
		let server = parseServerHello(sh.body);
		if (server.isHRR) {
			const retry = await this.doHelloRetry(ch, sh, server, resume);
			ch = retry.ch;
			sh = retry.sh;
			server = retry.server;
			sentEarly = false; // early data (if any was sent) is dropped across a retry
			earlyWrite = null;
		}
		this.suite = SUITES[server.cipher] ?? (() => { throw new Error('unsupported cipher: 0x' + server.cipher.toString(16)); })();
		this.thash = crypto.createHash(this.suite.hash); // the suite fixes the transcript hash
		for (const m of this.transcript) this.thash.update(m);
		this.transcript = [];
		this.addTranscript(sh.raw);
		if (!server.keyShare) throw new Error('ServerHello without key_share');
		// PSK accepted iff the server echoed pre_shared_key AND the suite hash matches
		// the ticket's (the binder/PSK are bound to that hash).
		const pskAccepted = !!resume && server.selectedIdentity != null && this.suite.hash === resume.ticket.hash;

		// 3) (EC)DHE + handshake keys (early_secret comes from the PSK when resumed)
		let ecdhe: Uint8Array;
		if (server.keyShare.group === Group.x25519mlkem768) {
			if (!hybrid) throw new Error('server chose X25519MLKEM768 but no hybrid share was offered');
			const ks = server.keyShare.pub; // ML-KEM-768 ciphertext (1088) || X25519 pubkey (32)
			const mlShared = await mlkem768Decapsulate(hybrid.mlkem, ks.subarray(0, 1088));
			const xShared = x25519Shared(hybrid.x, ks.subarray(1088));
			ecdhe = concat(mlShared, xShared); // combined secret = ML-KEM || X25519
		} else {
			const priv = ch.privs.get(server.keyShare.group);
			if (!priv) throw new Error('server chose a group we did not offer: ' + server.keyShare.group);
			ecdhe = ecdheShared(server.keyShare.group, priv, server.keyShare.pub);
		}
		const early = pskAccepted ? earlySecret(this.suite.hash, resume!.ticket.psk) : undefined;
		this.sched = deriveHandshake(this.suite.hash, ecdhe, this.th(), early);
		const sHs = trafficKey(this.suite.hash, this.sched.sHs, this.suite.keyLen);
		const cHs = trafficKey(this.suite.hash, this.sched.cHs, this.suite.keyLen);
		this.readDir = new AeadDir(this.suite.aead(sHs.key), sHs.iv);
		this.writeDir = new AeadDir(this.suite.aead(cHs.key), cHs.iv);

		// 4) EncryptedExtensions .. server Finished. When resumed, NO Certificate/CertVerify.
		let certs: Uint8Array[] = [];
		let staple: Uint8Array | null = null; // stapled OCSP (status_request on the leaf)
		let cv: { alg: number; sig: Uint8Array } | null = null;
		let thBeforeCV: Uint8Array = new Uint8Array(0);
		let eeEarly = false;
		let certReqContext: Uint8Array | null = null; // set if the server asks for a client cert
		for (;;) {
			const msg = await this.nextHandshakeMsg(true);
			if (!msg) throw new Error('connection closed before server Finished');
			if (msg.type === HandshakeType.finished) {
				const expect = finishedVerify(this.suite.hash, this.sched.sHs, this.th());
				const got = msg.body.bytes(msg.body.rem);
				if (!timingEqual(expect, got)) throw new Error('server Finished mismatch (bad verify_data)');
				this.addTranscript(msg.raw);
				break;
			}
			if (msg.type === HandshakeType.encryptedExtensions) {
				const ee = parseEE(msg.body);
				this.alpn = ee.alpn;
				eeEarly = ee.earlyData;
				this.opts.onAlpn?.(this.alpn);
			} else if (msg.type === HandshakeType.certificate) {
				({ certs, ocsp: staple } = parseCertificate(msg.body));
			} else if (msg.type === HandshakeType.compressedCertificate) {
				({ certs, ocsp: staple } = parseCompressedCertificate(msg.body)); // RFC 8879
			} else if (msg.type === HandshakeType.certificateVerify) {
				cv = { alg: msg.body.u16(), sig: msg.body.block(2).buf };
			} else if (msg.type === HandshakeType.certificateRequest) {
				certReqContext = new Uint8Array(msg.body.block(1).buf); // echo this in our Certificate
			}
			this.addTranscript(msg.raw);
			if (msg.type === HandshakeType.certificate || msg.type === HandshakeType.compressedCertificate) thBeforeCV = this.th(); // CV hash = up to (compressed) Certificate
		}

		// 4b) Certificate verification — only on a full (non-resumed) handshake.
		this.peerCertificates = certs;
		this.ocspStaple = staple;
		if (!pskAccepted && this.opts.verify !== false) {
			verifyChain(certs, this.opts.host);
			if (!cv) throw new Error('server did not send CertificateVerify');
			verifyCertificateVerify(certs[0]!, cv.alg, cv.sig, thBeforeCV);
			await checkRevocation(certs, staple, this.opts.ocsp ?? 'off');
		}
		this.resumed = pskAccepted;
		this.earlyAccepted = sentEarly && eeEarly && pskAccepted;

		// 5) App secrets (transcript up to server Finished)
		const app = appSecrets(this.sched, this.th());
		const sAp = trafficKey(this.suite.hash, app.sAp, this.suite.keyLen);
		const cAp = trafficKey(this.suite.hash, app.cAp, this.suite.keyLen);

		// 6) client CCS (compat); EndOfEarlyData if 0-RTT accepted; client Finished.
		this.t.write(plaintextRecord(ContentType.changeCipherSpec, Uint8Array.of(1)));
		if (this.earlyAccepted) {
			// EndOfEarlyData is the last message of the early-data stream → encrypted with
			// the client_early_traffic keys (RFC 8446 §4.5), continuing that record sequence.
			const eoed = new Writer().u8(HandshakeType.endOfEarlyData).block(3, () => {}).build();
			this.t.write(earlyWrite!.encrypt(ContentType.handshake, eoed));
			this.addTranscript(eoed);
		}
		// Client Certificate when asked (RFC 8446 §4.4.2). We hold no client cert, so send an
		// empty list: servers doing optional mTLS proceed; ones that require a cert fail cleanly
		// instead of hanging on a missing message.
		if (certReqContext !== null) {
			const cert = new Writer()
				.u8(HandshakeType.certificate)
				.block(3, (w) => {
					w.block(1, (ctx) => ctx.bytes(certReqContext!)); // echo certificate_request_context
					w.block(3, () => {}); // empty certificate_list
				})
				.build();
			this.t.write(this.writeDir!.encrypt(ContentType.handshake, cert));
			this.addTranscript(cert);
		}
		const verify = finishedVerify(this.suite.hash, this.sched.cHs, this.th());
		const finMsg = new Writer().u8(HandshakeType.finished).block(3, (w) => w.bytes(verify)).build();
		this.t.write(this.writeDir!.encrypt(ContentType.handshake, finMsg));
		this.addTranscript(finMsg);

		// 7) Switch to app keys; compute resumption master for future NewSessionTickets.
		this.appRead = new AeadDir(this.suite.aead(sAp.key), sAp.iv);
		this.appWrite = new AeadDir(this.suite.aead(cAp.key), cAp.iv);
		this.sApSecret = app.sAp;
		this.cApSecret = app.cAp;
		this.appMode = true;
		this.resMaster = resumptionMaster(this.suite.hash, this.sched.master, this.th());
		this.resHash = this.suite.hash;
		this.resCipher = server.cipher;
		// Handshake (and early) traffic keys are finished with: release their native handles now.
		this.readDir.destroy();
		this.writeDir!.destroy();
		earlyWrite?.destroy();
	}

	/** HelloRetryRequest (RFC 8446 §4.1.4): the server advertised a group we listed but
	 *  did not send a key_share for. Rewrite the transcript to message_hash(ClientHello1),
	 *  then resend a ClientHello with a key_share for the requested group (+ cookie). */
	private async doHelloRetry(
		ch: ReturnType<typeof buildClientHello>,
		hrr: { raw: Uint8Array },
		server: ParsedSH,
		resume: TlsOptions['resume']
	): Promise<{ ch: ReturnType<typeof buildClientHello>; sh: { type: number; raw: Uint8Array; body: Reader }; server: ParsedSH }> {
		const hash: HashAlg = SUITES[server.cipher]?.hash ?? 'sha256';
		const synthetic = concat(Uint8Array.of(HandshakeType.messageHash, 0, 0, hashLen(hash)), sha(hash, ch.bytes));
		this.transcript = [synthetic, hrr.raw];
		const g = server.selectedGroup;
		if (g == null || !(g === Group.x25519 || g === Group.secp256r1 || g === Group.secp384r1))
			throw new Error('HelloRetryRequest asked for a group we cannot negotiate: ' + g);
		// CH2 keeps CH1's random + session_id, and (when resuming) binds its PSK over the full
		// retry transcript — synthetic message_hash(CH1) || HRR || truncated CH2 (RFC 8446 §4.1.2).
		const ch2 = buildClientHello({ ...this.opts.fingerprint, keyShareGroups: [g] }, this.opts.host, resume ? { ...resume, earlyData: false } : undefined, server.cookie, undefined, {
			random: ch.random,
			sessionId: ch.sessionId,
			binderPrefix: concat(synthetic, hrr.raw)
		});
		this.addTranscript(ch2.bytes);
		this.t.write(plaintextRecord(ContentType.handshake, ch2.bytes));
		const sh = await this.nextHandshakeMsg(false);
		if (!sh || sh.type !== HandshakeType.serverHello) throw new Error('expected ServerHello after HelloRetryRequest');
		const server2 = parseServerHello(sh.body);
		if (server2.isHRR) throw new Error('second HelloRetryRequest (would loop)');
		return { ch: ch2, sh, server: server2 };
	}

	writeApp(data: Uint8Array): void {
		if (!this.appMode) throw new Error('handshake not finished');
		// TLSInnerPlaintext ≤ 2^14 (content + 1 type byte) → fragment at 16383 bytes/record.
		// One buffer, one socket write — lowest latency for small/medium writes.
		if (data.length) this.t.write(this.appWrite.encryptMany(ContentType.applicationData, data, 16384 - 1));
	}

	/** Streaming upload for a large body: encrypt a batch, await it onto the socket (which
	 *  yields to the event loop), then encrypt the next. The peer drains batch k while we
	 *  encrypt batch k+1 — overlaps CPU with I/O and paces to backpressure. */
	async writeAppStream(data: Uint8Array): Promise<void> {
		if (!this.appMode) throw new Error('handshake not finished');
		const BATCH = 16383 * 16; // ~256 KB of plaintext per flush (16 records sealed in parallel)
		for (let off = 0; off < data.length; off += BATCH) {
			const chunk = data.subarray(off, off + BATCH);
			await this.t.writeAsync(await this.appWrite.encryptManyAsync(ContentType.applicationData, chunk, 16384 - 1));
		}
	}

	/** Decrypted application data. NewSessionTicket → onTicket; KeyUpdate rotates keys. null = EOF. */
	async readApp(): Promise<Uint8Array | null> {
		if (!this.appMode) throw new Error('handshake not finished');
		return this.appRead.hasAsync ? this.readAppAsync() : this.readAppSync();
	}

	private async readAppSync(): Promise<Uint8Array | null> {
		for (;;) {
			const rec = await this.pullRecord();
			if (rec === null) return null;
			if (rec.type === ContentType.changeCipherSpec) continue;
			const d = this.appRead.decrypt(rec);
			const out = this.routeApp(d);
			if (out !== CONTINUE) return out;
		}
	}

	/** Native-AEAD (ChaCha) path: decrypt every buffered record in PARALLEL and keep a FIFO of
	 *  in-flight decrypts, returning them in wire order. The native crypto runs off-thread, so
	 *  N records in one socket chunk decrypt concurrently (~1 GB/s) instead of one at a time. */
	private async readAppAsync(): Promise<Uint8Array | null> {
		for (;;) {
			if (this.inflight.length === 0) {
				const rec = await this.pullRecord();
				if (rec === null) return null;
				this.dispatch(rec);
				for (let r = this.rr.next(); r; r = this.rr.next()) this.dispatch(r); // drain the chunk
				if (this.inflight.length === 0) continue; // only CCS seen → pull more
			}
			const h = this.inflight.shift()!;
			const d = await h.p; // wire order; a decrypt failure rejects here, after earlier records returned
			const out = this.routeApp(d); // a KeyUpdate record rotates appRead inside here
			if (this.appRead !== h.dir) this.redispatch(); // …so re-decrypt the queued records with the new key
			if (out !== CONTINUE) return out;
		}
	}

	/** Queue one record's async decrypt (seq is assigned now, in wire order). CCS carries no seq. */
	private dispatch(rec: { type: number; fragment: Uint8Array }): void {
		if (rec.type === ContentType.changeCipherSpec) return;
		const dir = this.appRead;
		const p = dir.decryptAsync(rec);
		p.catch(() => {}); // a discarded record's later rejection must not be an unhandledRejection
		this.inflight.push({ rec, dir, p });
	}

	/** After a KeyUpdate, re-decrypt the records still queued (dispatched under the old key) with
	 *  the new key, starting at its seq 0 — in queue order, which is wire order. */
	private redispatch(): void {
		for (const e of this.inflight) {
			e.dir = this.appRead;
			e.p = e.dir.decryptAsync(e.rec);
			e.p.catch(() => {});
		}
	}

	/** Route one decrypted record. Returns the app bytes to hand out, null on EOF/close_notify,
	 *  or the CONTINUE sentinel to keep reading (CCS already filtered; handshake handled inline). */
	private routeApp(d: { innerType: number; content: Uint8Array }): Uint8Array | null | typeof CONTINUE {
		if (d.innerType === ContentType.applicationData) return d.content;
		if (d.innerType === ContentType.alert) {
			if (d.content[1] === 0) return null; // close_notify
			throw new Error('TLS alert desc=' + d.content[1]);
		}
		if (d.innerType === ContentType.handshake) this.onPostHandshake(d.content);
		return CONTINUE;
	}

	/** Post-handshake messages: capture NewSessionTicket (resumption) and honor KeyUpdate
	 *  (rotate traffic keys). Parses whole messages within one record. */
	private onPostHandshake(data: Uint8Array): void {
		const r = new Reader(data);
		while (r.rem >= 4) {
			const type = r.u8();
			const body = r.block(3);
			if (type === HandshakeType.newSessionTicket) {
				if (this.opts.onTicket && this.resMaster) {
					const t = parseNewSessionTicket(body, this.resHash, this.resMaster, this.resCipher, this.alpn);
					if (t) this.opts.onTicket(t);
				}
			} else if (type === HandshakeType.keyUpdate) {
				this.handleKeyUpdate(body.rem >= 1 ? body.u8() : 0);
			}
		}
	}

	/** KeyUpdate (RFC 8446 §7.2): the server rotated its write key, so rotate our read key.
	 *  If it requested an update, reply with our own KeyUpdate and rotate our write key too
	 *  (reply encrypted with the OLD write key, then swap). */
	private handleKeyUpdate(requested: number): void {
		const h = this.suite.hash;
		this.sApSecret = updateTraffic(h, this.sApSecret);
		const sk = trafficKey(h, this.sApSecret, this.suite.keyLen);
		const oldRead = this.appRead;
		this.appRead = new AeadDir(this.suite.aead(sk.key), sk.iv);
		oldRead.destroy(); // in-flight async (WebCrypto) decrypts hold their own key, not this handle
		if (requested === 1) {
			const msg = new Writer().u8(HandshakeType.keyUpdate).block(3, (w) => w.u8(0)).build();
			this.t.write(this.appWrite.encrypt(ContentType.handshake, msg));
			this.cApSecret = updateTraffic(h, this.cApSecret);
			const ck = trafficKey(h, this.cApSecret, this.suite.keyLen);
			const oldWrite = this.appWrite;
			this.appWrite = new AeadDir(this.suite.aead(ck.key), ck.iv);
			oldWrite.destroy();
		}
	}

	close(): void {
		this.t.close();
		// Native key handles go now, not at the next GC. Reading after close() throws.
		this.appRead?.destroy();
		this.appWrite?.destroy();
		this.readDir?.destroy();
		this.writeDir?.destroy();
	}
}

function timingEqual(a: Uint8Array, b: Uint8Array): boolean {
	return a.length === b.length && crypto.timingSafeEqual(a, b);
}

interface ParsedSH {
	cipher: number;
	isHRR: boolean;
	keyShare: { group: number; pub: Uint8Array } | null;
	selectedIdentity: number | null; // pre_shared_key index echoed by the server (PSK accepted)
	selectedGroup: number | null; // HRR: the group the server wants a key_share for
	cookie?: Uint8Array; // HRR: to echo in the next ClientHello
}
function parseServerHello(r: Reader): ParsedSH {
	r.u16(); // legacy_version
	const random = r.bytes(32);
	r.block(1); // session_id echo
	const cipher = r.u16();
	r.u8(); // compression
	const isHRR = hex(random) === HRR_RANDOM;
	let keyShare: ParsedSH['keyShare'] = null;
	let selectedIdentity: number | null = null;
	let selectedGroup: number | null = null;
	let cookie: Uint8Array | undefined;
	const exts = r.block(2);
	while (exts.rem >= 4) {
		const t = exts.u16();
		const eb = exts.block(2);
		if (t === Ext.key_share) {
			if (isHRR) selectedGroup = eb.u16(); // HRR key_share = selected_group only (no pub)
			else {
				const group = eb.u16();
				const pub = eb.block(2).buf;
				keyShare = { group, pub };
			}
		} else if (t === Ext.pre_shared_key) {
			selectedIdentity = eb.u16();
		} else if (t === Ext.cookie) {
			cookie = new Uint8Array(eb.block(2).buf);
		}
	}
	return { cipher, isHRR, keyShare, selectedIdentity, selectedGroup, cookie };
}

/** Parse a NewSessionTicket → a resumption Ticket (PSK derived from the resumption
 *  master). Reads ticket_lifetime, ticket_age_add, nonce, ticket, and the early_data
 *  extension's max_early_data_size (0 = no 0-RTT). */
function parseNewSessionTicket(r: Reader, hash: HashAlg, resMaster: Uint8Array, cipher: number, alpn: string | null): Ticket | null {
	const lifetime = r.u32();
	const ageAdd = r.u32();
	const nonce = new Uint8Array(r.block(1).buf);
	const identity = new Uint8Array(r.block(2).buf);
	let maxEarlyData = 0;
	const exts = r.block(2);
	while (exts.rem >= 4) {
		const t = exts.u16();
		const eb = exts.block(2);
		if (t === Ext.early_data) maxEarlyData = eb.u32();
	}
	if (!identity.length) return null;
	const psk = resumptionPsk(hash, resMaster, nonce);
	return { identity, psk, hash, cipher, ageAdd, obtainedAt: Date.now(), lifetime, maxEarlyData, alpn };
}

/** TLS 1.3 Certificate: context(block1) + list(block3 of [cert(block3) ext(block2)]).
 *  Captures the leaf CertificateEntry's status_request extension (stapled OCSP). */
function parseCertificate(r: Reader): { certs: Uint8Array[]; ocsp: Uint8Array | null } {
	r.block(1); // certificate_request_context
	const list = r.block(3);
	const certs: Uint8Array[] = [];
	let ocsp: Uint8Array | null = null;
	while (list.rem >= 3) {
		const cert = list.block(3).buf;
		certs.push(new Uint8Array(cert)); // copy off the reader buffer
		const exts = list.block(2); // per-cert extensions
		while (exts.rem >= 4) {
			const t = exts.u16();
			const eb = exts.block(2);
			// status_request on the leaf → CertificateStatus { status_type(1=ocsp), OCSPResponse<u24> }
			if (t === Ext.status_request && certs.length === 1 && ocsp == null && eb.rem >= 4 && eb.u8() === 1) ocsp = new Uint8Array(eb.block(3).buf);
		}
	}
	return { certs, ocsp };
}

/** CompressedCertificate (RFC 8879): algorithm(u16) + uncompressed_length(u24) +
 *  compressed Certificate-message body. Decompress, then parse as a normal Certificate. */
function parseCompressedCertificate(r: Reader): { certs: Uint8Array[]; ocsp: Uint8Array | null } {
	const algo = r.u16();
	r.u24(); // uncompressed_length (the decompressors size themselves)
	const compressed = r.block(3).buf;
	let raw: Buffer;
	if (algo === 1) raw = zlib.inflateSync(compressed);
	else if (algo === 2) raw = zlib.brotliDecompressSync(compressed);
	else if (algo === 3 && typeof zlib.zstdDecompressSync === 'function') raw = zlib.zstdDecompressSync(compressed);
	else throw new Error('unsupported certificate compression algorithm ' + algo);
	return parseCertificate(new Reader(new Uint8Array(raw)));
}

/** EncryptedExtensions: negotiated ALPN + whether the server accepted 0-RTT (early_data).
 *  The EE body is `Extension extensions<0..2^16-1>` — a 2-byte length prefix then the list. */
function parseEE(r: Reader): { alpn: string | null; earlyData: boolean } {
	let alpn: string | null = null;
	let earlyData = false;
	const exts = r.block(2);
	while (exts.rem >= 4) {
		const t = exts.u16();
		const eb = exts.block(2);
		if (t === Ext.alpn) {
			const list = eb.block(2);
			alpn = Buffer.from(list.block(1).buf).toString();
		} else if (t === Ext.early_data) {
			earlyData = true;
		}
	}
	return { alpn, earlyData };
}
