// ClientHello extensions — one tiny builder each. The order in
// Fingerprint.extensions = order on the wire = what drives JA3/JA4. Adding or
// reordering an extension = edit the array; the assembler never changes.
import crypto from 'node:crypto';
import { Writer } from '../core/bytes';
import { Ext, TLS13 } from '../core/consts';

/** Dynamic context at assembly time (host + freshly generated key_share). */
export interface ExtCtx {
	host: string;
	shares: { group: number; pub: Uint8Array }[];
	/** GREASE value for this connection (null = no GREASE). Chrome reuses one
	 *  value across supported_groups[0], supported_versions[0], key_share[0]. */
	grease: number | null;
}

/** One extension: `type` (for JA3/JA4) + `body` (contents, without type+len header). */
export interface Extension {
	type: number;
	body(ctx: ExtCtx): Uint8Array;
}

const empty = (): Uint8Array => new Uint8Array(0);

export const serverName = (): Extension => ({
	type: Ext.server_name,
	body: (ctx) =>
		new Writer()
			.block(2, (list) => list.u8(0).block(2, (n) => n.bytes(Buffer.from(ctx.host))))
			.build()
});

export const supportedGroups = (groups: number[]): Extension => ({
	type: Ext.supported_groups,
	body: (ctx) =>
		new Writer()
			.block(2, (w) => {
				if (ctx.grease != null) w.u16(ctx.grease);
				groups.forEach((g) => w.u16(g));
			})
			.build()
});

export const ecPointFormats = (formats = [0]): Extension => ({
	type: Ext.ec_point_formats,
	body: () => new Writer().block(1, (w) => formats.forEach((f) => w.u8(f))).build()
});

export const signatureAlgorithms = (algs: number[]): Extension => ({
	type: Ext.signature_algorithms,
	body: () => new Writer().block(2, (w) => algs.forEach((a) => w.u16(a))).build()
});

export const alpn = (protocols: string[]): Extension => ({
	type: Ext.alpn,
	body: () =>
		new Writer().block(2, (list) => protocols.forEach((p) => list.block(1, (n) => n.bytes(Buffer.from(p))))).build()
});

/** supported_versions, ClientHello variant: list prefixed by 1 byte. */
export const supportedVersions = (versions = [TLS13]): Extension => ({
	type: Ext.supported_versions,
	body: (ctx) =>
		new Writer()
			.block(1, (w) => {
				if (ctx.grease != null) w.u16(ctx.grease);
				versions.forEach((v) => w.u16(v));
			})
			.build()
});

export const pskKeyExchangeModes = (modes = [1]): Extension => ({
	type: Ext.psk_key_exchange_modes,
	body: () => new Writer().block(1, (w) => modes.forEach((m) => w.u8(m))).build()
});

/** early_data indication (0-RTT) — empty body in a ClientHello. */
export const earlyData = (): Extension => ({ type: Ext.early_data, body: empty });

export const keyShare = (): Extension => ({
	type: Ext.key_share,
	body: (ctx) =>
		new Writer()
			.block(2, (list) => {
				// Chrome puts a GREASE key_share (1-byte dummy key) first.
				if (ctx.grease != null) list.u16(ctx.grease).block(2, (k) => k.u8(0));
				ctx.shares.forEach((s) => list.u16(s.group).block(2, (k) => k.bytes(s.pub)));
			})
			.build()
});

export const extendedMasterSecret = (): Extension => ({ type: Ext.extended_master_secret, body: empty });
export const renegotiationInfo = (): Extension => ({ type: Ext.renegotiation_info, body: () => Uint8Array.of(0) });
export const sessionTicket = (): Extension => ({ type: Ext.session_ticket, body: empty });

/** status_request OCSP (status_type=1, empty responder/extensions). */
export const statusRequest = (): Extension => ({
	type: Ext.status_request,
	body: () => Uint8Array.of(1, 0, 0, 0, 0)
});

/** compress_certificate: algorithms (1=zlib, 2=brotli, 3=zstd). */
export const compressCertificate = (algos = [2]): Extension => ({
	type: Ext.compress_certificate,
	body: () => new Writer().block(1, (w) => algos.forEach((a) => w.u16(a))).build()
});

/** signed_certificate_timestamp (SCT) — empty in ClientHello. */
export const signedCertTimestamp = (): Extension => ({ type: Ext.signed_certificate_timestamp, body: empty });

/** record_size_limit (RFC 8449), e.g. Firefox 0x4001. */
export const recordSizeLimit = (limit = 0x4001): Extension => ({
	type: 28,
	body: () => Uint8Array.of((limit >> 8) & 0xff, limit & 0xff)
});

/** application_settings (ALPS) — supported protocols, e.g. ['h2']. `newCodepoint`
 *  picks 17613 (Chrome ≥133) vs 17513 (older). */
export const applicationSettings = (protocols = ['h2'], newCodepoint = false): Extension => ({
	type: newCodepoint ? Ext.application_settings_new : Ext.application_settings,
	body: () =>
		new Writer().block(2, (list) => protocols.forEach((p) => list.block(1, (n) => n.bytes(Buffer.from(p))))).build()
});

/** GREASE ECH (encrypted_client_hello, type 65037) like Chrome/Safari send when
 *  they don't have a real ECH config: outer type + HPKE suite + random enc/payload.
 *  Servers that can't decrypt it ignore it. Only the ext TYPE is in JA3. */
export const encryptedClientHelloGrease = (): Extension => ({
	type: Ext.encrypted_client_hello,
	body: () =>
		new Writer()
			.u8(0) // ECHClientHelloType = outer
			.u16(0x0001) // HKDF-SHA256
			.u16(0x0001) // AEAD AES-128-GCM
			.u8(crypto.randomBytes(1)[0]!) // config_id
			.block(2, (w) => w.bytes(crypto.randomBytes(32))) // enc (X25519 pubkey-sized)
			.block(2, (w) => w.bytes(crypto.randomBytes(160))) // payload (GREASE)
			.build()
});

/** delegated_credentials (Firefox) — the sigalg list it accepts. */
export const delegatedCredentials = (algs = [0x0403, 0x0503, 0x0603, 0x0203]): Extension => ({
	type: 34,
	body: () => new Writer().block(2, (w) => algs.forEach((a) => w.u16(a))).build()
});

/** GREASE / unknown extension (RFC 8701): empty body unless given. */
export const grease = (type: number, body: Uint8Array = new Uint8Array(0)): Extension => ({ type, body: () => body });
