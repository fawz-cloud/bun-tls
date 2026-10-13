// QUIC packet protection (RFC 9001 §5): build a protected Initial packet and parse/decrypt
// an incoming long-header packet. AEAD over the unprotected header as AAD, then header
// protection over the first byte + packet number using a ciphertext sample.
import { aesGcm } from '../core/crypto';
import { concat } from '../core/bytes';
import { writeVarint, readVarint } from './varint';
import { hpMask, type PacketKeys } from './crypto';

const VERSION1 = Uint8Array.of(0, 0, 0, 1);
export const PKT = { initial: 0x00, handshake: 0x02 } as const;

/** 12-byte AEAD nonce = iv XOR packet-number (right-aligned, big-endian). */
function nonce(iv: Uint8Array, pn: number): Uint8Array {
	const n = Uint8Array.from(iv);
	// pn fits in 4 bytes for our use; XOR into the last 4.
	n[11] ^= pn & 0xff;
	n[10] ^= (pn >>> 8) & 0xff;
	n[9] ^= (pn >>> 16) & 0xff;
	n[8] ^= (pn >>> 24) & 0xff;
	return n;
}

/** Build a protected long-header packet (Initial or Handshake). pnLen fixed at 4. */
export function buildPacket(type: number, dcid: Uint8Array, scid: Uint8Array, token: Uint8Array, payload: Uint8Array, pn: number, keys: PacketKeys): Uint8Array {
	const pnLen = 4;
	const first = 0xc0 | (type << 4) | (pnLen - 1); // long, fixed bit, type, pnlen
	const pnBytes = Uint8Array.of((pn >>> 24) & 0xff, (pn >>> 16) & 0xff, (pn >>> 8) & 0xff, pn & 0xff);
	const lengthField = writeVarint(pnLen + payload.length + 16); // pn + ciphertext + tag
	const header = concat(
		Uint8Array.of(first),
		VERSION1,
		Uint8Array.of(dcid.length),
		dcid,
		Uint8Array.of(scid.length),
		scid,
		type === PKT.initial ? concat(writeVarint(token.length), token) : new Uint8Array(0),
		lengthField,
		pnBytes
	);
	const aead = aesGcm(16)(keys.key);
	const ct = aead.seal(nonce(keys.iv, pn), header, payload); // ciphertext + 16-byte tag
	// Header protection: sample 16 bytes of ciphertext starting 4 bytes into the PN field.
	const pnOffset = header.length - pnLen;
	const sampleStart = 4 - pnLen; // into ct
	const mask = hpMask(keys.hp, ct.subarray(sampleStart, sampleStart + 16));
	const out = concat(header, ct);
	out[0] ^= mask[0]! & 0x0f;
	for (let i = 0; i < pnLen; i++) out[pnOffset + i] ^= mask[1 + i]!;
	return out;
}

export interface ParsedPacket {
	type: number;
	dcid: Uint8Array;
	scid: Uint8Array;
	pn: number;
	payload: Uint8Array;
	end: number; // offset just past this packet in the datagram (for coalesced packets)
}

/** Remove header protection + decrypt one long-header packet at `off`. */
export function parsePacket(dg: Uint8Array, off: number, keys: PacketKeys): ParsedPacket {
	const start = off;
	const first0 = dg[off];
	const type = (first0! >> 4) & 0x03;
	off += 1 + 4; // first byte + version
	const dcidLen = dg[off++]!;
	const dcid = dg.subarray(off, off + dcidLen);
	off += dcidLen;
	const scidLen = dg[off++]!;
	const scid = dg.subarray(off, off + scidLen);
	off += scidLen;
	if (type === PKT.initial) {
		const tok = readVarint(dg, off);
		off += tok.len + tok.value; // skip token
	}
	const lenField = readVarint(dg, off);
	off += lenField.len;
	const pnOffset = off;
	// Header protection removal: sample starts 4 bytes into the PN field.
	const mask = hpMask(keys.hp, dg.subarray(pnOffset + 4, pnOffset + 20));
	const first = first0! ^ (mask[0]! & 0x0f);
	const pnLen = (first & 0x03) + 1;
	let pn = 0;
	const pnBytes = new Uint8Array(pnLen);
	for (let i = 0; i < pnLen; i++) {
		pnBytes[i] = dg[pnOffset + i]! ^ mask[1 + i]!;
		pn = pn * 256 + pnBytes[i]!;
	}
	const ctStart = pnOffset + pnLen;
	const ctLen = lenField.value - pnLen;
	const ct = dg.subarray(ctStart, ctStart + ctLen);
	// AAD = unprotected header (first byte + pn restored).
	const aad = Uint8Array.from(dg.subarray(start, ctStart));
	aad[0] = first;
	for (let i = 0; i < pnLen; i++) aad[pnOffset - start + i] = pnBytes[i]!;
	const aead = aesGcm(16)(keys.key);
	const payload = aead.open(nonce(keys.iv, pn), aad, ct);
	return { type, dcid: new Uint8Array(dcid), scid: new Uint8Array(scid), pn, payload, end: ctStart + ctLen };
}

if (import.meta.main) {
	// Round-trip: protect then parse recovers the payload (AEAD + HP are inverses).
	const { initialKeys } = await import('./crypto');
	const dcid = Uint8Array.from(Buffer.from('8394c8f03e515708', 'hex'));
	const { client } = initialKeys(dcid);
	const payload = Uint8Array.from(Buffer.from('060040f1010000ed0303', 'hex')); // CRYPTO frame prefix
	const pkt = buildPacket(PKT.initial, dcid, new Uint8Array(0), new Uint8Array(0), payload, 2, client);
	const parsed = parsePacket(pkt, 0, client);
	if (parsed.pn !== 2 || Buffer.compare(Buffer.from(parsed.payload), Buffer.from(payload)) !== 0) throw new Error('packet round-trip failed');
	console.log('quic packet protect/parse round-trip ok (pn', parsed.pn, 'payload', parsed.payload.length, 'bytes)');
}
