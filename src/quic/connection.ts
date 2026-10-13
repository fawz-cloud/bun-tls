// A QUIC v1 client connection (RFC 9000/9001): drives the TLS 1.3 handshake carried in
// CRYPTO frames across the Initial + Handshake packet-number spaces, installs handshake and
// 1-RTT keys, and then exposes 1-RTT send/recv for the HTTP/3 layer. Loss recovery is
// minimal (retransmit the client flight on timeout) — enough for a short request.
import crypto from 'node:crypto';
import { lookup } from 'node:dns/promises';
import { Reader, concat, hex } from '../core/bytes';
import { Cipher, Group, SigAlg, HandshakeType, Ext } from '../core/consts';
import {
	deriveHandshake,
	appSecrets,
	finishedVerify,
	ecdheShared,
	sha,
	hashLen,
	type HashAlg,
	type Schedule
} from '../core/crypto';
import { buildClientHello } from '../tls/clienthello';
import * as E from '../tls/extensions';
import { verifyChain, verifyCertificateVerify } from '../tls/verify';
import zlib from 'node:zlib';
import { writeVarint } from './varint';
import { initialKeys, packetKeys, type PacketKeys } from './crypto';
import { buildPacket, parsePacket, buildShort, parseShort, PKT, longPacketType, longPacketEnd } from './packet';
import { parseFrames, cryptoFrame, ackFrame, type Frame } from './frames';

const SUITE_HASH: Record<number, HashAlg> = { [Cipher.TLS_AES_128_GCM_SHA256]: 'sha256', [Cipher.TLS_AES_256_GCM_SHA384]: 'sha384', [Cipher.TLS_CHACHA20_POLY1305_SHA256]: 'sha256' };
const SUITE_KEYLEN: Record<number, number> = { [Cipher.TLS_AES_128_GCM_SHA256]: 16, [Cipher.TLS_AES_256_GCM_SHA384]: 32, [Cipher.TLS_CHACHA20_POLY1305_SHA256]: 32 };

interface UdpSock {
	send(data: Uint8Array, port: number, addr: string): void;
	close(): void;
}

type Space = 'initial' | 'handshake';

export class QuicConnection {
	private sock!: UdpSock;
	private addr = '';
	private dcid: Uint8Array; // peer's connection id (server SCID once learned)
	private scid: Uint8Array;
	private origDcid: Uint8Array;
	private keys: { initial: { c: PacketKeys; s: PacketKeys }; handshake?: { c: PacketKeys; s: PacketKeys }; app?: { c: PacketKeys; s: PacketKeys } };
	private pn = { initial: 0, handshake: 0, app: 0 };
	private largest = { initial: -1, handshake: -1, app: -1 }; // largest received PN per space (for ACKs)
	private cryptoBuf: Record<Space, { chunks: Map<number, Uint8Array>; consumed: number }> = {
		initial: { chunks: new Map(), consumed: 0 },
		handshake: { chunks: new Map(), consumed: 0 }
	};
	private dgQueue: Uint8Array[] = [];
	private dgWaiter: ((b: Uint8Array | null) => void) | null = null;
	private transcript: Uint8Array[] = [];
	private priv!: crypto.KeyObject;
	private hash: HashAlg = 'sha256';
	private keyLen = 16;
	private sched!: Schedule;
	private suite = 0;
	private shDone = false;
	private hsComplete = false;
	appKeyLen = 16;
	handshakeDone = false;
	private ch!: Uint8Array;
	private retryToken: Uint8Array = new Uint8Array(0);
	private retried = false;
	closed = false;

	constructor(private host: string, private port = 443) {
		this.scid = new Uint8Array(crypto.randomBytes(8));
		this.origDcid = new Uint8Array(crypto.randomBytes(8));
		this.dcid = this.origDcid;
		const ik = initialKeys(this.origDcid);
		this.keys = { initial: { c: ik.client, s: ik.server } };
	}

	private spaceKeys(sp: Space) {
		return sp === 'initial' ? this.keys.initial : this.keys.handshake!;
	}

	/** Open the UDP socket + complete the QUIC/TLS handshake (install 1-RTT keys). */
	async connect(timeoutMs = 10000): Promise<void> {
		const { address } = await lookup(this.host, { family: 4 });
		this.addr = address;
		this.sock = (await Bun.udpSocket({
			socket: {
				data: (_s: unknown, buf: Uint8Array) => {
					const b = new Uint8Array(buf);
					if (this.dgWaiter) {
						const w = this.dgWaiter;
						this.dgWaiter = null;
						w(b);
					} else this.dgQueue.push(b);
				}
			}
		})) as unknown as UdpSock;

		// Build + send the Initial (CRYPTO=ClientHello + PADDING to ≥1200).
		this.ch = this.buildCH();
		this.transcript.push(this.ch);
		this.sendInitialFlight();

		const deadline = Date.now() + timeoutMs;
		while (!this.hsComplete && Date.now() < deadline) {
			const dg = await this.recvDatagram(deadline - Date.now());
			if (!dg) {
				this.sendInitialFlight(); // retransmit on timeout (minimal loss recovery)
				continue;
			}
			this.processDatagram(dg);
		}
		if (!this.hsComplete) throw new Error('QUIC handshake timed out');
	}

	private buildCH(): Uint8Array {
		const tpParam = (id: number, val: Uint8Array) => concat(writeVarint(id), writeVarint(val.length), val);
		const tp = concat(
			tpParam(0x01, writeVarint(30000)),
			tpParam(0x03, writeVarint(1472)),
			tpParam(0x04, writeVarint(1048576)),
			tpParam(0x05, writeVarint(262144)),
			tpParam(0x06, writeVarint(262144)),
			tpParam(0x07, writeVarint(262144)),
			tpParam(0x08, writeVarint(100)),
			tpParam(0x09, writeVarint(100)),
			tpParam(0x0f, this.scid)
		);
		const fp = {
			ciphers: [Cipher.TLS_AES_128_GCM_SHA256, Cipher.TLS_AES_256_GCM_SHA384, Cipher.TLS_CHACHA20_POLY1305_SHA256],
			keyShareGroups: [Group.x25519],
			extensions: [
				E.serverName(),
				E.supportedGroups([Group.x25519, Group.secp256r1, Group.secp384r1]),
				E.ecPointFormats([0]),
				E.signatureAlgorithms([SigAlg.ecdsa_secp256r1_sha256, SigAlg.rsa_pss_rsae_sha256, SigAlg.rsa_pkcs1_sha256, SigAlg.ecdsa_secp384r1_sha384, SigAlg.rsa_pss_rsae_sha384]),
				E.supportedVersions(),
				E.pskKeyExchangeModes([1]),
				E.keyShare(),
				E.alpn(['h3']),
				E.grease(0x39, tp)
			]
		};
		// buildClientHello takes the x25519 key share (from the pool); read its private key back out.
		const built = buildClientHello(fp as never, this.host);
		this.priv = built.privs.get(Group.x25519)!;
		let b = built.bytes;
		const sidOff = 4 + 2 + 32;
		const sidLen = b[sidOff]!;
		b = concat(b.subarray(0, sidOff), Uint8Array.of(0), b.subarray(sidOff + 1 + sidLen)); // empty legacy_session_id (RFC 9001 §8.4)
		const hl = b.length - 4;
		b[1] = (hl >> 16) & 0xff;
		b[2] = (hl >> 8) & 0xff;
		b[3] = hl & 0xff;
		return b;
	}

	private sendInitialFlight(): void {
		const payload = concat(cryptoFrame(0, this.ch), new Uint8Array(1200)); // PADDING → datagram ≥1200
		const pkt = buildPacket(PKT.initial, this.dcid, this.scid, this.retryToken, payload, this.pn.initial++, this.keys.initial.c);
		this.sock.send(pkt, this.port, this.addr);
	}

	/** Retry (RFC 9000 §17.2.5 / 9001 §5.2): adopt the server SCID as the new DCID, re-derive
	 *  Initial keys from it, and resend the ClientHello with the retry token. Once only. */
	private handleRetry(dg: Uint8Array, off: number): void {
		if (this.retried) return;
		this.retried = true;
		let i = off + 1 + 4;
		i += 1 + dg[i]!; // dcid
		const sl = dg[i++]!;
		const newScid = new Uint8Array(dg.subarray(i, i + sl));
		i += sl;
		this.retryToken = new Uint8Array(dg.subarray(i, dg.length - 16)); // token = rest minus integrity tag
		this.dcid = newScid;
		const ik = initialKeys(newScid);
		this.keys.initial = { c: ik.client, s: ik.server };
		this.pn.initial = 0;
		this.largest.initial = -1;
		this.sendInitialFlight();
	}

	private async recvDatagram(timeoutMs: number): Promise<Uint8Array | null> {
		if (this.dgQueue.length) return this.dgQueue.shift()!;
		return new Promise<Uint8Array | null>((res) => {
			this.dgWaiter = res;
			setTimeout(() => {
				if (this.dgWaiter === res) {
					this.dgWaiter = null;
					res(null);
				}
			}, Math.max(50, Math.min(timeoutMs, 2000)));
		});
	}

	private processDatagram(dg: Uint8Array): void {
		let off = 0;
		const ackNeed: { initial?: boolean; handshake?: boolean } = {};
		while (off < dg.length) {
			const first = dg[off]!;
			if ((first & 0x80) === 0) {
				// short header (1-RTT) — handled by the h3 read loop, not during handshake
				this.on1rtt(dg, off);
				break;
			}
			const type = longPacketType(dg, off);
			if (type === 0x03) {
				this.handleRetry(dg, off);
				return;
			}
			const sp: Space | null = type === PKT.initial ? 'initial' : type === PKT.handshake ? 'handshake' : null;
			const end = longPacketEnd(dg, off);
			if (sp === null || (sp === 'handshake' && !this.keys.handshake)) {
				off = end; // can't/needn't decrypt (0-RTT, or Handshake before we have keys)
				continue;
			}
			try {
				const p = parsePacket(dg, off, this.spaceKeys(sp).s, sp === 'handshake' ? this.keyLen : 16);
				if (p.scid.length) this.dcid = p.scid; // adopt the server's connection id
				this.largest[sp] = Math.max(this.largest[sp], p.pn);
				ackNeed[sp] = true;
				const ff = parseFrames(p.payload);
				for (const f of ff) this.onFrame(sp, f);
				if (sp === 'initial') this.maybeDeriveHandshake(); // install hs keys before a coalesced Handshake packet in the SAME datagram
			} catch {
				/* undecryptable (reordered) — skip */
			}
			off = end;
		}
		// Acknowledge what we processed, and advance the handshake.
		if (ackNeed.initial) this.sendAck('initial');
		this.maybeDeriveHandshake();
		this.maybeFinishHandshake(!!ackNeed.handshake);
	}

	private onFrame(sp: Space, f: Frame): void {
		if (f.type === 'crypto') {
			const cb = this.cryptoBuf[sp];
			cb.chunks.set(f.offset, f.data);
		} else if (f.type === 'handshake_done') this.handshakeDone = true;
		else if (f.type === 'close') throw new Error(`QUIC CONNECTION_CLOSE code=${f.code} ${f.reason}`);
	}

	/** Contiguous CRYPTO bytes available from `consumed` onward in a space. */
	private drainCrypto(sp: Space): Uint8Array {
		const cb = this.cryptoBuf[sp];
		const parts: Uint8Array[] = [];
		for (;;) {
			const next = cb.chunks.get(cb.consumed);
			if (!next) break;
			parts.push(next);
			cb.chunks.delete(cb.consumed);
			cb.consumed += next.length;
		}
		return parts.length ? concat(...parts) : new Uint8Array(0);
	}

	// TLS message reassembly buffers per space.
	private tlsBuf: Record<Space, Uint8Array> = { initial: new Uint8Array(0), handshake: new Uint8Array(0) };

	private *tlsMessages(sp: Space): Generator<{ type: number; raw: Uint8Array; body: Reader }> {
		this.tlsBuf[sp] = concat(this.tlsBuf[sp], this.drainCrypto(sp));
		let buf = this.tlsBuf[sp];
		let off = 0;
		while (buf.length - off >= 4) {
			const len = (buf[off + 1]! << 16) | (buf[off + 2]! << 8) | buf[off + 3]!;
			if (buf.length - off < 4 + len) break;
			const raw = buf.subarray(off, off + 4 + len);
			yield { type: raw[0]!, raw, body: new Reader(raw.subarray(4)) };
			off += 4 + len;
		}
		this.tlsBuf[sp] = buf.subarray(off);
	}

	private maybeDeriveHandshake(): void {
		if (this.shDone) return;
		for (const msg of this.tlsMessages('initial')) {
			if (msg.type !== HandshakeType.serverHello) continue;
			this.transcript.push(msg.raw);
			const sh = parseSH(msg.body);
			this.suite = sh.cipher;
			this.hash = SUITE_HASH[sh.cipher] ?? 'sha256';
			this.keyLen = SUITE_KEYLEN[sh.cipher] ?? 16;
			this.appKeyLen = this.keyLen;
			if (this.keyLen === 32 && sh.cipher === Cipher.TLS_CHACHA20_POLY1305_SHA256) throw new Error('QUIC: ChaCha20 suite not supported (header protection differs)');
			if (!sh.keyShare) throw new Error('QUIC ServerHello without key_share');
			const ecdhe = ecdheShared(sh.keyShare.group, this.priv, sh.keyShare.pub);
			this.sched = deriveHandshake(this.hash, ecdhe, this.th());
			this.keys.handshake = { c: packetKeys(this.hash, this.sched.cHs, this.keyLen), s: packetKeys(this.hash, this.sched.sHs, this.keyLen) };
			this.shDone = true;
			break;
		}
	}

	private certs: Uint8Array[] = [];
	private cv: { alg: number; sig: Uint8Array } | null = null;
	private thBeforeCV: Uint8Array = new Uint8Array(0);
	private serverFinSeen = false;

	/** Transcript-Hash of the messages so far. */
	private th(): Uint8Array {
		return sha(this.hash, concat(...this.transcript));
	}

	private maybeFinishHandshake(gotHandshakePkt: boolean): void {
		if (!this.shDone || this.hsComplete) return;
		for (const msg of this.tlsMessages('handshake')) {
			if (msg.type === HandshakeType.encryptedExtensions) {
				this.transcript.push(msg.raw);
			} else if (msg.type === HandshakeType.certificate) {
				this.certs = parseCert(msg.body);
				this.transcript.push(msg.raw);
				this.thBeforeCV = this.th();
			} else if (msg.type === HandshakeType.compressedCertificate) {
				this.certs = parseCompressedCert(msg.body);
				this.transcript.push(msg.raw);
				this.thBeforeCV = this.th();
			} else if (msg.type === HandshakeType.certificateVerify) {
				this.cv = { alg: msg.body.u16(), sig: new Uint8Array(msg.body.block(2).buf) };
				this.transcript.push(msg.raw);
			} else if (msg.type === HandshakeType.finished) {
				const expect = finishedVerify(this.hash, this.sched.sHs, this.th());
				const got = new Uint8Array(msg.body.bytes(msg.body.rem));
				if (!crypto.timingSafeEqual(expect, got)) throw new Error('QUIC: server Finished mismatch');
				this.transcript.push(msg.raw);
				this.serverFinSeen = true;
			}
		}
		if (!this.serverFinSeen) {
			if (gotHandshakePkt) this.sendAck('handshake');
			return;
		}
		// Verify the certificate chain + CertVerify, derive app keys, send our Finished.
		verifyChain(this.certs, this.host);
		if (!this.cv) throw new Error('QUIC: no CertificateVerify');
		verifyCertificateVerify(this.certs[0]!, this.cv.alg, this.cv.sig, this.thBeforeCV);
		const th = this.th(); // CH..server Finished: app secrets + our Finished (no client cert here)
		const app = appSecrets(this.sched, th);
		this.keys.app = { c: packetKeys(this.hash, app.cAp, this.keyLen), s: packetKeys(this.hash, app.sAp, this.keyLen) };
		const verify = finishedVerify(this.hash, this.sched.cHs, th);
		const fin = concat(Uint8Array.of(HandshakeType.finished), Uint8Array.of(0, 0, hashLen(this.hash)), verify);
		// Send: ACK(handshake) + our Finished in a Handshake packet.
		const hsPayload = concat(ackFrame(this.largest.handshake), cryptoFrame(0, fin));
		this.sock.send(buildPacket(PKT.handshake, this.dcid, this.scid, new Uint8Array(0), hsPayload, this.pn.handshake++, this.keys.handshake!.c, this.keyLen), this.port, this.addr);
		this.hsComplete = true;
	}

	private sendAck(sp: Space): void {
		if (this.largest[sp] < 0) return;
		const keys = this.spaceKeys(sp).c;
		const type = sp === 'initial' ? PKT.initial : PKT.handshake;
		// Initial packets must be ≥1200 only for the client's first flight; ACK-only can be small.
		this.sock.send(buildPacket(type, this.dcid, this.scid, new Uint8Array(0), ackFrame(this.largest[sp]), this.pn[sp]++, keys, sp === 'handshake' ? this.keyLen : 16), this.port, this.addr);
	}

	// ── 1-RTT (application) data, for the HTTP/3 layer ──────────────────────────────
	private app1rttFrames: Frame[] = [];

	private on1rtt(dg: Uint8Array, off: number): void {
		if (!this.keys.app) return;
		try {
			const p = parseShort(dg, off, this.scid.length, this.keys.app.s, this.appKeyLen);
			this.largest.app = Math.max(this.largest.app, p.pn);
			for (const f of parseFrames(p.payload)) {
				if (f.type === 'handshake_done') this.handshakeDone = true;
				else if (f.type === 'close') throw new Error(`QUIC CONNECTION_CLOSE code=${f.code} ${f.reason}`);
				else this.app1rttFrames.push(f);
			}
		} catch {
			/* undecryptable */
		}
	}

	/** Send frame bytes in a 1-RTT packet (plus an ACK of what we've received). */
	send1rtt(frames: Uint8Array): void {
		const payload = this.largest.app >= 0 ? concat(ackFrame(this.largest.app), frames) : frames;
		this.sock.send(buildShort(this.dcid, payload, this.pn.app++, this.keys.app!.c, this.appKeyLen), this.port, this.addr);
	}

	/** Await the next batch of 1-RTT STREAM/other frames (auto-ACKs, drops handshake pkts). */
	async recv1rtt(timeoutMs = 8000): Promise<Frame[]> {
		const deadline = Date.now() + timeoutMs;
		for (;;) {
			if (this.app1rttFrames.length) {
				const f = this.app1rttFrames;
				this.app1rttFrames = [];
				if (this.largest.app >= 0) this.sock.send(buildShort(this.dcid, ackFrame(this.largest.app), this.pn.app++, this.keys.app!.c, this.appKeyLen), this.port, this.addr);
				return f;
			}
			const dg = await this.recvDatagram(deadline - Date.now());
			if (!dg) {
				if (Date.now() >= deadline) return [];
				continue;
			}
			// A datagram may still coalesce leftover Handshake packets ahead of 1-RTT.
			let off = 0;
			while (off < dg.length) {
				if ((dg[off]! & 0x80) === 0) {
					this.on1rtt(dg, off);
					break;
				}
				off = longPacketEnd(dg, off);
			}
		}
	}

	close(): void {
		if (this.closed) return;
		this.closed = true;
		try {
			this.sock.close();
		} catch {
			/* already gone */
		}
	}
}

// ── minimal TLS message parsers (QUIC carries these in CRYPTO frames) ──────────────
function parseSH(r: Reader): { cipher: number; keyShare: { group: number; pub: Uint8Array } | null } {
	r.u16();
	r.bytes(32);
	r.block(1);
	const cipher = r.u16();
	r.u8();
	let keyShare: { group: number; pub: Uint8Array } | null = null;
	const exts = r.block(2);
	while (exts.rem >= 4) {
		const t = exts.u16();
		const eb = exts.block(2);
		if (t === Ext.key_share) keyShare = { group: eb.u16(), pub: new Uint8Array(eb.block(2).buf) };
	}
	return { cipher, keyShare };
}
function parseCert(r: Reader): Uint8Array[] {
	r.block(1);
	const list = r.block(3);
	const out: Uint8Array[] = [];
	while (list.rem >= 3) {
		out.push(new Uint8Array(list.block(3).buf));
		list.block(2);
	}
	return out;
}
function parseCompressedCert(r: Reader): Uint8Array[] {
	const algo = r.u16();
	r.u24();
	const comp = r.block(3).buf;
	const raw = algo === 1 ? zlib.inflateSync(comp) : algo === 2 ? zlib.brotliDecompressSync(comp) : zlib.zstdDecompressSync(comp);
	return parseCert(new Reader(new Uint8Array(raw)));
}

export { hex };
