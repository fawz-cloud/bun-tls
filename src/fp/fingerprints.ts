// Fingerprint presets. Each preset = a Fingerprint (ciphers + extensions in wire
// order + key_share group). Add a preset (e.g. a captured 'dart') = add an entry;
// the handshake never changes. The extension order here IS the JA3/JA4 sent.
import { Cipher, Group, SigAlg } from '../core/consts';
import type { Fingerprint } from '../tls/clienthello';
import * as E from '../tls/extensions';

/** Clean modern TLS 1.3 (no GREASE) — meant to "just work like curl", not to
 *  impersonate anyone. Good enough for 200s against normal servers + JA3 echo. */
export const modern = (): Fingerprint => ({
	ciphers: [Cipher.TLS_AES_128_GCM_SHA256, Cipher.TLS_AES_256_GCM_SHA384, Cipher.TLS_CHACHA20_POLY1305_SHA256],
	keyShareGroups: [Group.x25519],
	extensions: [
		E.serverName(),
		E.extendedMasterSecret(),
		E.renegotiationInfo(),
		E.supportedGroups([Group.x25519, Group.secp256r1, Group.secp384r1]),
		E.ecPointFormats([0]),
		E.sessionTicket(),
		E.alpn(['http/1.1']),
		E.statusRequest(),
		E.signatureAlgorithms([
			SigAlg.ecdsa_secp256r1_sha256,
			SigAlg.rsa_pss_rsae_sha256,
			SigAlg.rsa_pkcs1_sha256,
			SigAlg.ecdsa_secp384r1_sha384,
			SigAlg.rsa_pss_rsae_sha384,
			SigAlg.rsa_pkcs1_sha384,
			SigAlg.rsa_pss_rsae_sha512,
			SigAlg.rsa_pkcs1_sha512
		]),
		E.supportedVersions(),
		E.pskKeyExchangeModes([1]),
		E.keyShare()
	]
});

// Captured from dart:io (Dart SDK 3.13.3) on 2026-10-12 via tls.peet.ws, the same
// HttpClient the Dart relay uses → matches the Flutter app's dart:io ClientHello.
//   ja3  = 771,4867-4865-4866-52393-52392-49195-49199-49196-49200-49161-49171-49162-49172-156-157-47-53,0-23-65281-10-11-35-13-51-45-43,29-23-24,0
//   ja3_hash = 9225d95490794840d9d5f1f94d339285
//   ja4  = t13d1710_5b57614c22b0_78e6aca7449b
// No ALPN, no GREASE, no status_request/compress_cert. Cipher list includes
// TLS 1.2 suites as fingerprint filler — we only speak 1.3, and supported_versions
// = TLS 1.3 makes the server pick a 1.3 suite anyway. The sigalg ORDER matters (JA4_c).
export const dart = (): Fingerprint => ({
	ciphers: [
		0x1303, 0x1301, 0x1302, // TLS 1.3: chacha, aes128-gcm, aes256-gcm
		0xcca9, 0xcca8, // ecdhe chacha20
		0xc02b, 0xc02f, 0xc02c, 0xc030, // ecdhe aes-gcm
		0xc009, 0xc013, 0xc00a, 0xc014, // ecdhe aes-cbc
		0x009c, 0x009d, // rsa aes-gcm
		0x002f, 0x0035 // rsa aes-cbc
	],
	keyShareGroups: [Group.x25519],
	extensions: [
		E.serverName(),
		E.extendedMasterSecret(),
		E.renegotiationInfo(),
		E.supportedGroups([Group.x25519, Group.secp256r1, Group.secp384r1]),
		E.ecPointFormats([0]),
		E.sessionTicket(),
		E.signatureAlgorithms([
			SigAlg.ecdsa_secp256r1_sha256, // 0403
			SigAlg.rsa_pss_rsae_sha256, // 0804
			SigAlg.rsa_pkcs1_sha256, // 0401
			SigAlg.ecdsa_secp384r1_sha384, // 0503
			SigAlg.rsa_pss_rsae_sha384, // 0805
			SigAlg.rsa_pkcs1_sha384, // 0501
			SigAlg.rsa_pss_rsae_sha512, // 0806
			SigAlg.rsa_pkcs1_sha512, // 0601
			SigAlg.rsa_pkcs1_sha1 // 0201
		]),
		E.keyShare(),
		E.pskKeyExchangeModes([1]),
		E.supportedVersions() // [TLS13] — values aren't in JA3/JA4, only ext presence
	]
});

// ---------------------------------------------------------------------------
// Browser presets transcribed from utls (refraction-networking/utls) u_parrots.go:
// cipher list, extension set + order, curves and sigalgs follow the utls spec, so
// the JA3/JA3N match the published values for that browser version (verified against
// an echo server). They are NOT full browser clones. Known differences:
//  - key_share: the presets send X25519MLKEM768 (post-quantum hybrid) + X25519 (+ P-256 for
//    Firefox), matching the real browsers; the hybrid is fully negotiated (ML-KEM via
//    WebCrypto). P-256/P-384 via HelloRetryRequest also work. Only FFDHE groups are
//    advertised-but-not-implemented (no mainstream server requires FFDHE).
//  - ALPN: http/1.1 only (real browsers offer h2,http/1.1) — the JA4 ALPN byte differs.
//  - supported_versions: TLS 1.3 only. GREASE values and the GREASE ECH payload are
//    random per connection, as in browsers, but not byte-identical to any capture.

/** Chromium sigalgs (Chrome/Edge 131): 0403,0804,0401,0503,0805,0501,0806,0601. */
const CHROME_SIGALGS = [
	SigAlg.ecdsa_secp256r1_sha256,
	SigAlg.rsa_pss_rsae_sha256,
	SigAlg.rsa_pkcs1_sha256,
	SigAlg.ecdsa_secp384r1_sha384,
	SigAlg.rsa_pss_rsae_sha384,
	SigAlg.rsa_pkcs1_sha384,
	SigAlg.rsa_pss_rsae_sha512,
	SigAlg.rsa_pkcs1_sha512
];

const CHROME_CIPHERS = [
	0x1301, 0x1302, 0x1303, // AES128-GCM, AES256-GCM, CHACHA20
	0xc02b, 0xc02f, 0xc02c, 0xc030, // ECDHE AES-GCM (ecdsa/rsa)
	0xcca9, 0xcca8, // ECDHE CHACHA20 (ecdsa/rsa)
	0xc013, 0xc014, // ECDHE AES-CBC (rsa)
	0x009c, 0x009d, // RSA AES-GCM
	0x002f, 0x0035 // RSA AES-CBC
];

/** Chrome 131 (and Edge 131) — utls HelloChrome_131. GREASE + permuted exts.
 *  ALPS uses the OLD codepoint 17513; Chrome 133+/155 switch to 17613 (pass
 *  `true` to applicationSettings). curves = GREASE,MLKEM768,x25519,P256,P384. */
export const chrome131 = (): Fingerprint => ({
	ciphers: CHROME_CIPHERS,
	keyShareGroups: [Group.x25519mlkem768, Group.x25519], // real Chrome sends both shares
	grease: true,
	permute: true,
	extensions: [
		E.serverName(),
		E.extendedMasterSecret(),
		E.renegotiationInfo(),
		E.supportedGroups([Group.x25519mlkem768, Group.x25519, Group.secp256r1, Group.secp384r1]),
		E.ecPointFormats([0]),
		E.sessionTicket(),
		E.alpn(['http/1.1']),
		E.statusRequest(),
		E.signatureAlgorithms(CHROME_SIGALGS),
		E.signedCertTimestamp(),
		E.keyShare(),
		E.pskKeyExchangeModes([1]),
		E.supportedVersions(),
		E.compressCertificate([2]), // brotli
		E.applicationSettings(['h2'], false), // ALPS 17513 (131); 133+/155 use 17613
		E.encryptedClientHelloGrease()
	]
});

/** Firefox 148 — utls HelloFirefox_148. No GREASE, fixed ext order. Drops
 *  session_ticket + psk_key_exchange_modes (present in FF ≤120), adds SCT and
 *  zlib+brotli+zstd cert-compression. curves incl MLKEM768, P521, FFDHE2048/3072. */
export const firefox148 = (): Fingerprint => ({
	ciphers: [
		0x1301, 0x1303, 0x1302, // AES128-GCM, CHACHA20, AES256-GCM
		0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, // ECDHE GCM/CHACHA (ecdsa/rsa)
		0xc00a, 0xc009, 0xc013, 0xc014, // ECDHE AES-CBC
		0x009c, 0x009d, // RSA AES-GCM
		0x002f, 0x0035 // RSA AES-CBC
	],
	keyShareGroups: [Group.x25519mlkem768, Group.x25519, Group.secp256r1], // Firefox sends these shares
	extensions: [
		E.serverName(),
		E.extendedMasterSecret(),
		E.renegotiationInfo(),
		E.supportedGroups([
			Group.x25519mlkem768,
			Group.x25519,
			Group.secp256r1,
			Group.secp384r1,
			Group.secp521r1,
			Group.ffdhe2048,
			Group.ffdhe3072
		]),
		E.ecPointFormats([0]),
		E.alpn(['http/1.1']),
		E.statusRequest(),
		E.delegatedCredentials([
			SigAlg.ecdsa_secp256r1_sha256,
			SigAlg.ecdsa_secp384r1_sha384,
			SigAlg.ecdsa_secp521r1_sha512,
			SigAlg.ecdsa_sha1
		]),
		E.signedCertTimestamp(),
		E.keyShare(),
		E.supportedVersions(),
		E.signatureAlgorithms([
			SigAlg.ecdsa_secp256r1_sha256,
			SigAlg.ecdsa_secp384r1_sha384,
			SigAlg.ecdsa_secp521r1_sha512,
			SigAlg.rsa_pss_rsae_sha256,
			SigAlg.rsa_pss_rsae_sha384,
			SigAlg.rsa_pss_rsae_sha512,
			SigAlg.rsa_pkcs1_sha256,
			SigAlg.rsa_pkcs1_sha384,
			SigAlg.rsa_pkcs1_sha512,
			SigAlg.ecdsa_sha1,
			SigAlg.rsa_pkcs1_sha1
		]),
		E.recordSizeLimit(0x4001),
		E.compressCertificate([1, 2, 3]), // zlib, brotli, zstd
		E.encryptedClientHelloGrease()
	]
});

export { CHROME_SIGALGS };

export const PRESETS: Record<string, () => Fingerprint> = { modern, dart, chrome131, firefox148 };

