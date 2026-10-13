// QUIC packet protection crypto (RFC 9001). Initial keys come from the client's chosen
// Destination Connection ID; handshake/1-RTT keys come from the TLS 1.3 traffic secrets
// with QUIC's "quic key"/"quic iv"/"quic hp" labels. Reuses the TLS HKDF from core/crypto.
import crypto from 'node:crypto';
import { hkdfExtract, expandLabel, type HashAlg } from '../core/crypto';

// QUIC v1 initial salt (RFC 9001 §5.2).
const INITIAL_SALT = Uint8Array.from(Buffer.from('38762cf7f55934b34d179ae6a4c80cadccbb7f0a', 'hex'));

export interface PacketKeys {
	key: Uint8Array; // AEAD key (AES-128-GCM for Initial)
	iv: Uint8Array; // 12-byte nonce base
	hp: Uint8Array; // header-protection key
	secret: Uint8Array; // the traffic secret (for key updates)
}

/** key/iv/hp from a traffic secret, with QUIC labels. keyLen 16 (AES-128) or 32 (AES-256). */
export function packetKeys(h: HashAlg, secret: Uint8Array, keyLen = 16): PacketKeys {
	return {
		key: expandLabel(h, secret, 'quic key', new Uint8Array(0), keyLen),
		iv: expandLabel(h, secret, 'quic iv', new Uint8Array(0), 12),
		hp: expandLabel(h, secret, 'quic hp', new Uint8Array(0), keyLen),
		secret
	};
}

/** Initial secrets + keys for both directions, derived from the client DCID. */
export function initialKeys(dcid: Uint8Array): { client: PacketKeys; server: PacketKeys } {
	const initial = hkdfExtract('sha256', INITIAL_SALT, dcid);
	const clientSecret = expandLabel('sha256', initial, 'client in', new Uint8Array(0), 32);
	const serverSecret = expandLabel('sha256', initial, 'server in', new Uint8Array(0), 32);
	return { client: packetKeys('sha256', clientSecret, 16), server: packetKeys('sha256', serverSecret, 16) };
}

/** Header-protection mask: AES-ECB(hp, sample)[0..5] for AES; sample is 16 bytes of ciphertext. */
export function hpMask(hp: Uint8Array, sample: Uint8Array): Uint8Array {
	const c = crypto.createCipheriv(hp.length === 16 ? 'aes-128-ecb' : 'aes-256-ecb', hp, null);
	c.setAutoPadding(false);
	return new Uint8Array(concatBuf(c.update(sample), c.final())).subarray(0, 5);
}
const concatBuf = (a: Buffer, b: Buffer): Buffer => Buffer.concat([a, b]);

if (import.meta.main) {
	// RFC 9001 Appendix A.1 test vectors.
	const dcid = Uint8Array.from(Buffer.from('8394c8f03e515708', 'hex'));
	const { client, server } = initialKeys(dcid);
	const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
	const want = {
		ck: '1f369613dd76d5467730efcbe3b1a22d', ci: 'fa044b2f42a3fd3b46fb255c', ch: '9f50449e04a0e810283a1e9933adedd2',
		sk: 'cf3a5331653c364c88f0f379b6067e37', si: '0ac1493ca1905853b0bba03e', sh: 'c206b8d9b9f0f37644430b490eeaa314'
	};
	const got = { ck: hex(client.key), ci: hex(client.iv), ch: hex(client.hp), sk: hex(server.key), si: hex(server.iv), sh: hex(server.hp) };
	for (const k of Object.keys(want) as (keyof typeof want)[]) if (got[k] !== want[k]) throw new Error(`initialKeys ${k}: got ${got[k]} want ${want[k]}`);
	console.log('quic initial keys ok (RFC 9001 A.1)');
}
