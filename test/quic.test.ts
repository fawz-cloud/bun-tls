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

console.log('quic: OK');
