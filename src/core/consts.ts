// TLS number registry (RFC 8446 + IANA). One place → easy to add/maintain.

export const ContentType = {
	changeCipherSpec: 20,
	alert: 21,
	handshake: 22,
	applicationData: 23
} as const;

export const HandshakeType = {
	clientHello: 1,
	serverHello: 2,
	newSessionTicket: 4,
	endOfEarlyData: 5,
	messageHash: 254,
	encryptedExtensions: 8,
	certificate: 11,
	certificateRequest: 13,
	certificateVerify: 15,
	finished: 20,
	keyUpdate: 24,
	compressedCertificate: 25
} as const;

export const Ext = {
	server_name: 0,
	status_request: 5,
	supported_groups: 10,
	ec_point_formats: 11,
	signature_algorithms: 13,
	alpn: 16,
	signed_certificate_timestamp: 18,
	extended_master_secret: 23,
	compress_certificate: 27,
	session_ticket: 35,
	early_data: 42,
	pre_shared_key: 41,
	supported_versions: 43,
	cookie: 44,
	psk_key_exchange_modes: 45,
	key_share: 51,
	application_settings: 17513, // ALPS (old codepoint, Chrome ≤132)
	application_settings_new: 17613, // ALPS (new codepoint, Chrome ≥133)
	encrypted_client_hello: 65037, // ECH (0xfe0d)
	renegotiation_info: 0xff01
} as const;

/** TLS 1.3 cipher suites. */
export const Cipher = {
	TLS_AES_128_GCM_SHA256: 0x1301,
	TLS_AES_256_GCM_SHA384: 0x1302,
	TLS_CHACHA20_POLY1305_SHA256: 0x1303
} as const;

export const Group = {
	x25519: 0x001d,
	secp256r1: 0x0017,
	secp384r1: 0x0018,
	secp521r1: 0x0019,
	ffdhe2048: 0x0100,
	ffdhe3072: 0x0101,
	x25519mlkem768: 0x11ec // 4588, post-quantum (Chrome 131+/FF/Safari 26). Listed in
	// supported_groups for the fingerprint; we send a key_share only for x25519
	// (no ML-KEM impl) — doesn't change JA3/JA4 (key_share contents aren't hashed).
} as const;

export const SigAlg = {
	ecdsa_secp256r1_sha256: 0x0403,
	ecdsa_secp384r1_sha384: 0x0503,
	ecdsa_secp521r1_sha512: 0x0603,
	rsa_pss_rsae_sha256: 0x0804,
	rsa_pss_rsae_sha384: 0x0805,
	rsa_pss_rsae_sha512: 0x0806,
	rsa_pkcs1_sha256: 0x0401,
	rsa_pkcs1_sha384: 0x0501,
	rsa_pkcs1_sha512: 0x0601,
	ecdsa_sha1: 0x0203,
	rsa_pkcs1_sha1: 0x0201
} as const;

export const TLS12 = 0x0303;
export const TLS13 = 0x0304;

/** GREASE values (RFC 8701): 0x0a0a, 0x1a1a, ... 0xfafa. */
export const GREASE = [0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa];
export const isGrease = (v: number): boolean => (v & 0x0f0f) === 0x0a0a && (v >> 8) === (v & 0xff);
