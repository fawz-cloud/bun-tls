// QUIC core (RFC 9000 varints, RFC 9001 Initial packet protection), offline vs spec vectors.
import assert from 'node:assert';
import { writeVarint, readVarint } from '../src/quic/varint';
import { initialKeys, packetKeys, hpCipher } from '../src/quic/crypto';
import { buildPacket, parsePacket, buildShort, parseShort, PKT } from '../src/quic/packet';

// varints vs RFC 9000 §16 examples
assert.equal(Buffer.from(writeVarint(15293)).toString('hex'), '7bbd', 'varint 15293');
assert.equal(readVarint(writeVarint(494878333), 0).value, 494878333, 'varint roundtrip');

// Initial keys byte-exact vs RFC 9001 Appendix A.1
const { client, server } = initialKeys(new Uint8Array(Buffer.from('8394c8f03e515708', 'hex')));
assert.equal(Buffer.from(client.key).toString('hex'), '1f369613dd76d5467730efcbe3b1a22d', 'client initial key (RFC 9001 A.1)');
assert.equal(Buffer.from(client.iv).toString('hex'), 'fa044b2f42a3fd3b46fb255c', 'client initial iv');
assert.equal(Buffer.from(server.hp).toString('hex'), 'c206b8d9b9f0f37644430b490eeaa314', 'server initial hp');

// packet protect → parse recovers the payload (AEAD + header protection are inverses)
const dcid = new Uint8Array(Buffer.from('8394c8f03e515708', 'hex'));
const payload = new Uint8Array(Buffer.from('060040f1010000ed', 'hex'));
const pkt = buildPacket(PKT.initial, dcid, new Uint8Array(0), new Uint8Array(0), payload, 2, client);
const p = parsePacket(pkt, 0, client);
assert.equal(p.pn, 2, 'packet number recovered');
assert.equal(Buffer.from(p.payload).toString('hex'), '060040f1010000ed', 'payload recovered');

// Header-protection masks vs RFC 9001 A.2 (client) / A.3 (server), through the cached cipher.
const hex = (s: string) => new Uint8Array(Buffer.from(s, 'hex'));
assert.equal(Buffer.from(hpCipher(client.hp)(hex('d1b1c98dd7689fb8ec11d242b123dc9b'))).toString('hex').slice(0, 10), '437b9aec36', 'client HP mask (RFC 9001 A.2)');
assert.equal(Buffer.from(hpCipher(server.hp)(hex('2cd0991cd25b0aac406a5816b6394100'))).toString('hex').slice(0, 10), '2ec0d8356a', 'server HP mask (RFC 9001 A.3)');

// 1-RTT packets: 200 per key set through one cached AEAD + HP cipher, AES-128 and AES-256.
for (const keyLen of [16, 32]) {
	const keys = packetKeys(keyLen === 16 ? 'sha256' : 'sha384', crypto.getRandomValues(new Uint8Array(keyLen === 16 ? 32 : 48)), keyLen);
	const scid = crypto.getRandomValues(new Uint8Array(8));
	for (let pn = 0; pn < 200; pn++) {
		const body = crypto.getRandomValues(new Uint8Array(20 + ((pn * 37) % 1300)));
		const pkt = buildShort(scid, body, pn, keys, keyLen);
		const got = parseShort(pkt, 0, scid.length, keys, keyLen);
		assert.equal(got.pn, pn, `1-RTT pn ${pn} (aes-${keyLen * 8})`);
		assert.deepEqual(got.payload, body, `1-RTT payload ${pn} (aes-${keyLen * 8})`);
	}
	const pkt = buildShort(scid, new Uint8Array(40), 7, keys, keyLen);
	pkt[pkt.length - 1]! ^= 1;
	assert.throws(() => parseShort(pkt, 0, scid.length, keys, keyLen), `tampered 1-RTT packet rejected (aes-${keyLen * 8})`);
}

// ── Truncated packet numbers decode against the largest received (RFC 9000 Appendix A.3) ──
{
	const { decodePn } = await import('../src/quic/packet');
	assert.equal(decodePn(0xa82f30ea, 0x9b32, 2), 0xa82f9b32, 'RFC 9000 A.3 example');
	assert.equal(decodePn(255, 0x03, 1), 259, '1-byte pn past 255 does not wrap back to 3');
	assert.equal(decodePn(300, 0xff, 1), 255, 'a late (reordered) packet decodes below largest');
	assert.equal(decodePn(-1, 2, 4), 2, 'first packet');
	for (let largest = 0; largest < 70000; largest += 997)
		for (const len of [1, 2, 4]) {
			const next = largest + 1 + (largest % 7);
			assert.equal(decodePn(largest, next % 2 ** (8 * len), len), next, `pn ${next} from ${len} byte(s) after ${largest}`);
		}
}

// ── ACKs name exactly the packets received (never a missing one: that would stop the resend) ──
{
	const { PnRanges, Reassembler } = await import('../src/quic/frames');
	/** Decode an ACK frame back into the set of packet numbers it acknowledges. */
	const acked = (f: Uint8Array): Set<number> => {
		let i = 0;
		const v = () => {
			const r = readVarint(f, i);
			i += r.len;
			return r.value;
		};
		assert.equal(v(), 0x02, 'ACK frame type');
		let hi = v();
		v(); // delay
		const n = v();
		let lo = hi - v();
		const out = new Set<number>();
		for (let k = lo; k <= hi; k++) out.add(k);
		for (let r = 0; r < n; r++) {
			hi = lo - v() - 2;
			lo = hi - v();
			for (let k = lo; k <= hi; k++) out.add(k);
		}
		return out;
	};
	const pr = new PnRanges();
	for (const pn of [0, 1, 2, 4, 5, 6, 8, 9]) assert.ok(pr.add(pn), `pn ${pn} new`);
	assert.equal(pr.add(5), false, 'duplicate detected');
	assert.deepEqual([...acked(pr.ackFrame())].sort((a, b) => a - b), [0, 1, 2, 4, 5, 6, 8, 9], 'gaps at 3 and 7 are not acked');
	let seed = 7;
	const rnd = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
	for (let t = 0; t < 200; t++) {
		const got = new PnRanges();
		const received = new Set<number>();
		const pns = Array.from({ length: 300 }, (_, k) => k).filter(() => rnd() < 0.9).sort(() => rnd() - 0.5);
		for (const pn of pns) {
			got.add(pn);
			received.add(pn);
		}
		const a = acked(got.ackFrame());
		for (const pn of a) assert.ok(received.has(pn), `trial ${t}: acked pn ${pn} that never arrived`);
		assert.ok(a.has(Math.max(...received)), `trial ${t}: largest acked`);
	}

	// Data resent cut at different boundaries, duplicated and out of order still reassembles.
	const data = crypto.getRandomValues(new Uint8Array(5000));
	for (let t = 0; t < 100; t++) {
		const pieces: [number, Uint8Array][] = [];
		for (let k = 0; k < 3; k++) // three different cuttings of the same bytes (original + 2 resends)
			for (let o = 0; o < data.length; ) {
				const len = 1 + Math.floor(rnd() * 900);
				pieces.push([o, data.subarray(o, o + len)]);
				o += len;
			}
		pieces.sort(() => rnd() - 0.5);
		const re = new Reassembler();
		const out: Uint8Array[] = [];
		for (const [o, d] of pieces) {
			re.push(o, d);
			out.push(re.take());
		}
		assert.deepEqual(Buffer.concat(out), Buffer.from(data), `trial ${t}: reassembled bytes`);
	}
}

console.log('quic: OK');
