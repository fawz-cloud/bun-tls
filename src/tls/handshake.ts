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
	clientEarlyTraffic
} from '../core/crypto';
import { chacha20Poly1305 } from '../core/chacha';
import type { Fingerprint, ResumeSpec } from './clienthello';
import { buildClientHello } from './clienthello';
import { AeadDir, plaintextRecord, RecordReader } from './record';
import type { Transport } from './transport';
import type { Ticket } from './resumption';
import { verifyCertificateVerify, verifyChain } from './verify';
import crypto from 'node:crypto';

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
	/** Negotiated ALPN read from EncryptedExtensions (informational). */
	onAlpn?: (proto: string | null) => void;
	/** Resume from a stored ticket (pre_shared_key). Enables 0-RTT if resume.earlyData. */
	resume?: ResumeSpec;
	/** Request bytes to send as 0-RTT early data (only used when resume.earlyData). */
	earlyData?: Uint8Array;
	/** Called for each NewSessionTicket the server sends (store for later resumption). */
	onTicket?: (t: Ticket) => void;
}

export class TlsClient {
	private rr = new RecordReader();
	private hsbuf: Uint8Array = new Uint8Array(0); // handshake message reassembly
	private transcript: Uint8Array[] = [];
	private suite!: Suite;
	private sched!: Schedule;
	private readDir!: AeadDir; // server→client (active once keys exist)
	private writeDir: AeadDir | null = null; // client→server, encrypted
	private appRead!: AeadDir;
	private appWrite!: AeadDir;
	private appMode = false;
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
	/** Server accepted our pre_shared_key (resumed handshake). */
	resumed = false;
	/** Server accepted our 0-RTT early data (the request was delivered in the CH flight). */
	earlyAccepted = false;

	constructor(
		private t: Transport,
		private opts: TlsOptions
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
		this.transcript.push(raw);
	}
	private th(): Uint8Array {
		return concat(...this.transcript);
	}

	async handshake(): Promise<void> {
		const resume = this.opts.resume;
		// 1) ClientHello (+ pre_shared_key + early_data when resuming)
		let ch = buildClientHello(this.opts.fingerprint, this.opts.host, resume);
		this.ja3 = ch.ja3;
		this.ja3Hash = ch.ja3Hash;
		this.ja3n = ch.ja3n;
		this.ja3nHash = ch.ja3nHash;
		this.ja4 = ch.ja4;
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
				const cet = clientEarlyTraffic(suite.hash, ch.earlySecret, ch.bytes);
				const k = trafficKey(suite.hash, cet, suite.keyLen);
				earlyWrite = new AeadDir(suite.aead(k.key), k.iv);
				this.t.write(earlyWrite.encryptMany(ContentType.applicationData, this.opts.earlyData, 16384 - 1));
				sentEarly = true;
			}
		}

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
		this.addTranscript(sh.raw);
		this.suite = SUITES[server.cipher] ?? (() => { throw new Error('unsupported cipher: 0x' + server.cipher.toString(16)); })();
		if (!server.keyShare) throw new Error('ServerHello without key_share');
		// PSK accepted iff the server echoed pre_shared_key AND the suite hash matches
		// the ticket's (the binder/PSK are bound to that hash).
		const pskAccepted = !!resume && server.selectedIdentity != null && this.suite.hash === resume.ticket.hash;

		// 3) ECDHE + handshake keys (early_secret comes from the PSK when resumed)
		const priv = ch.privs.get(server.keyShare.group);
		if (!priv) throw new Error('server chose a group we did not offer: ' + server.keyShare.group);
		const ecdhe = ecdheShared(server.keyShare.group, priv, server.keyShare.pub);
		const early = pskAccepted ? earlySecret(this.suite.hash, resume!.ticket.psk) : undefined;
		this.sched = deriveHandshake(this.suite.hash, ecdhe, this.th(), early);
		const sHs = trafficKey(this.suite.hash, this.sched.sHs, this.suite.keyLen);
		const cHs = trafficKey(this.suite.hash, this.sched.cHs, this.suite.keyLen);
		this.readDir = new AeadDir(this.suite.aead(sHs.key), sHs.iv);
		this.writeDir = new AeadDir(this.suite.aead(cHs.key), cHs.iv);

		// 4) EncryptedExtensions .. server Finished. When resumed, NO Certificate/CertVerify.
		let certs: Uint8Array[] = [];
		let cv: { alg: number; sig: Uint8Array } | null = null;
		let thBeforeCV: Uint8Array = new Uint8Array(0);
		let eeEarly = false;
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
				certs = parseCertificate(msg.body);
			} else if (msg.type === HandshakeType.certificateVerify) {
				cv = { alg: msg.body.u16(), sig: msg.body.block(2).buf };
			}
			this.addTranscript(msg.raw);
			if (msg.type === HandshakeType.certificate) thBeforeCV = this.th(); // CV hash = up to Certificate
		}

		// 4b) Certificate verification — only on a full (non-resumed) handshake.
		if (!pskAccepted && this.opts.verify !== false) {
			verifyChain(certs, this.opts.host);
			if (!cv) throw new Error('server did not send CertificateVerify');
			verifyCertificateVerify(certs[0]!, cv.alg, cv.sig, this.suite.hash, thBeforeCV);
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
		const verify = finishedVerify(this.suite.hash, this.sched.cHs, this.th());
		const finMsg = new Writer().u8(HandshakeType.finished).block(3, (w) => w.bytes(verify)).build();
		this.t.write(this.writeDir!.encrypt(ContentType.handshake, finMsg));
		this.addTranscript(finMsg);

		// 7) Switch to app keys; compute resumption master for future NewSessionTickets.
		this.appRead = new AeadDir(this.suite.aead(sAp.key), sAp.iv);
		this.appWrite = new AeadDir(this.suite.aead(cAp.key), cAp.iv);
		this.appMode = true;
		this.resMaster = resumptionMaster(this.suite.hash, this.sched.master, this.th());
		this.resHash = this.suite.hash;
		this.resCipher = server.cipher;
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
		const ch2 = buildClientHello({ ...this.opts.fingerprint, keyShareGroups: [g] }, this.opts.host, resume ? { ...resume, earlyData: false } : undefined, server.cookie);
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
		const BATCH = 16383 * 16; // ~256 KB of plaintext per flush
		for (let off = 0; off < data.length; off += BATCH) {
			const chunk = data.subarray(off, off + BATCH);
			await this.t.writeAsync(this.appWrite.encryptMany(ContentType.applicationData, chunk, 16384 - 1));
		}
	}

	/** Decrypted application data. NewSessionTicket → onTicket; KeyUpdate ignored. null = EOF. */
	async readApp(): Promise<Uint8Array | null> {
		if (!this.appMode) throw new Error('handshake not finished');
		for (;;) {
			const rec = await this.pullRecord();
			if (rec === null) return null;
			if (rec.type === ContentType.changeCipherSpec) continue;
			const d = this.appRead.decrypt(rec);
			if (d.innerType === ContentType.applicationData) return d.content;
			if (d.innerType === ContentType.alert) {
				if (d.content[1] === 0) return null; // close_notify
				throw new Error('TLS alert desc=' + d.content[1]);
			}
			if (d.innerType === ContentType.handshake) this.onPostHandshake(d.content);
		}
	}

	/** Post-handshake messages: capture NewSessionTicket as a resumption ticket; ignore
	 *  KeyUpdate. Parses whole messages within one record (tickets are small). */
	private onPostHandshake(data: Uint8Array): void {
		if (!this.opts.onTicket || !this.resMaster) return;
		const r = new Reader(data);
		while (r.rem >= 4) {
			const type = r.u8();
			const body = r.block(3);
			if (type === HandshakeType.newSessionTicket) {
				const t = parseNewSessionTicket(body, this.resHash, this.resMaster, this.resCipher, this.alpn);
				if (t) this.opts.onTicket(t);
			}
		}
	}

	close(): void {
		this.t.close();
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

/** TLS 1.3 Certificate: context(block1) + list(block3 of [cert(block3) ext(block2)]). */
function parseCertificate(r: Reader): Uint8Array[] {
	r.block(1); // certificate_request_context
	const list = r.block(3);
	const certs: Uint8Array[] = [];
	while (list.rem >= 3) {
		const cert = list.block(3).buf;
		certs.push(new Uint8Array(cert)); // copy off the reader buffer
		list.block(2); // per-cert extensions (ignored)
	}
	return certs;
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
