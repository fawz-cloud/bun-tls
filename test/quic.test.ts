// QUIC core (RFC 9000 varints, RFC 9001 Initial packet protection), offline vs spec vectors.
import assert from 'node:assert';
import { writeVarint, readVarint } from '../src/quic/varint';
import { initialKeys } from '../src/quic/crypto';
import { buildPacket, parsePacket, PKT } from '../src/quic/packet';

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

console.log('quic: OK');
