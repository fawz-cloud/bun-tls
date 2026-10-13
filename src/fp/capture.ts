// fromClientHello(bytes|hex) → Fingerprint that replays a CAPTURED ClientHello
// byte-for-byte. Unlike fromJa3 (which is lossy — a JA3 drops extension order and every
// extension body), this reproduces the exact cipher list, extension order AND each
// extension's raw bytes, so the JA3/JA3N/JA4 match the capture exactly.
//
// Capture a real client's ClientHello with Wireshark / tcpdump / a proxy, copy it as hex
// (the handshake message, or the whole TLS record), and replay it:
//   const fp = fromClientHello(hexFromWireshark);
//   await request({ url, fingerprint: fp });
//
// The inherently per-connection fields are regenerated, as every real client also varies
// them: client random, session_id, and the key_share public keys (none are in JA3/JA4).
// server_name is rewritten to the request's host. Session-specific extensions
// (pre_shared_key, early_data) are dropped.
import { Reader, fromHex } from '../core/bytes';
import { Ext, Group } from '../core/consts';
import * as E from '../tls/extensions';
import type { Extension } from '../tls/extensions';
import type { Fingerprint } from '../tls/clienthello';

// Groups we can actually produce a key_share for (x25519mlkem768 is handled by the
// handshake's hybrid pre-build; the others by the standard generator).
const KS_GROUPS = new Set<number>([Group.x25519, Group.secp256r1, Group.secp384r1, Group.x25519mlkem768]);

/** Rebuild a Fingerprint from a captured ClientHello (raw bytes or a hex string). */
export function fromClientHello(input: Uint8Array | string): Fingerprint {
	let buf = typeof input === 'string' ? fromHex(input.replace(/[^0-9a-fA-F]/g, '')) : input;
	// Accept a full TLS record (0x16 = handshake) by stripping its 5-byte header.
	if (buf[0] === 0x16 && buf[5] === 0x01) buf = buf.subarray(5);
	const r = new Reader(buf);
	if (r.u8() !== 1) throw new Error('not a ClientHello (handshake type != 1)');
	const body = r.block(3);
	body.u16(); // legacy_version
	body.bytes(32); // random — regenerated per connection
	body.block(1); // session_id — regenerated
	const ciphers: number[] = [];
	const cr = body.block(2);
	while (cr.rem >= 2) ciphers.push(cr.u16()); // kept verbatim, including any GREASE
	const compression: number[] = [];
	const comp = body.block(1);
	while (comp.rem >= 1) compression.push(comp.u8());

	const extensions: Extension[] = [];
	const keyShareGroups: number[] = [];
	if (body.rem >= 2) {
		const er = body.block(2);
		while (er.rem >= 4) {
			const type = er.u16();
			const raw = new Uint8Array(er.block(2).buf);
			if (type === Ext.server_name) {
				extensions.push(E.serverName()); // rewritten to the request host
			} else if (type === Ext.key_share) {
				// Fresh key shares, but for the same groups the capture offered (skip GREASE
				// and 1-byte dummy shares). ponytail: the GREASE dummy share is not re-added
				// (grease:false); it isn't in JA3/JA4, so the fingerprint is unaffected.
				const ks = new Reader(raw).block(2); // client_shares vector
				while (ks.rem >= 4) {
					const g = ks.u16();
					ks.block(2); // skip this share's public key (we regenerate our own)
					if (KS_GROUPS.has(g)) keyShareGroups.push(g);
				}
				extensions.push(E.keyShare());
			} else if (type === Ext.pre_shared_key || type === Ext.early_data) {
				// session-specific — cannot be replayed on a fresh connection
			} else {
				extensions.push(E.grease(type, raw)); // byte-exact passthrough
			}
		}
	}
	return {
		ciphers,
		keyShareGroups: keyShareGroups.length ? keyShareGroups : [Group.x25519],
		extensions,
		compression,
		grease: false,
		permute: false
	};
}
