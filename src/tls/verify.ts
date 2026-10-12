// Server certificate verification (on by default; pass verify:false to skip, like
// curl_cffi). Three layers:
//  1. leaf matches the hostname (SAN) and is within its validity window,
//  2. chain: each cert is signed by the next; the top one chains to a system root
//     (node:tls.rootCertificates ∪ bundled cacert.pem),
//  3. CertificateVerify: the handshake signature made with the leaf public key
//     (anti-MITM).
import crypto from 'node:crypto';
import tls from 'node:tls';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { HashAlg, sha } from '../core/crypto';
import { concat } from '../core/bytes';
import { verifyOcsp, fetchOcsp } from './ocsp';

// Trust store = Bun's built-in roots (tls.rootCertificates, often incomplete)
// UNION the bundled Mozilla cacert.pem (scratch/bun-tls/cacert.pem). Roots are
// indexed by their full subject DN so a cert's issuer DN finds the candidate
// issuer in O(1) — avoids a brute-force signature scan over every root (~250
// RSA verifies = tens of ms per handshake).
let rootsBySubject: Map<string, crypto.X509Certificate[]> | null = null;
function rootStore(): Map<string, crypto.X509Certificate[]> {
	if (rootsBySubject) return rootsBySubject;
	const pems = [...tls.rootCertificates];
	const bundle = join(import.meta.dir, '..', '..', 'cacert.pem');
	if (existsSync(bundle)) {
		for (const m of readFileSync(bundle, 'utf8').matchAll(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g)) {
			pems.push(m[0]);
		}
	}
	rootsBySubject = new Map();
	for (const pem of pems) {
		try {
			const c = new crypto.X509Certificate(pem);
			(rootsBySubject.get(c.subject) ?? rootsBySubject.set(c.subject, []).get(c.subject)!).push(c);
		} catch {
			/* skip unparseable root */
		}
	}
	return rootsBySubject;
}

/** verify() throws on key-type mismatch (EC cert vs RSA root) — wrap it. */
const signedBy = (cert: crypto.X509Certificate, issuer: crypto.X509Certificate): boolean => {
	try {
		return cert.verify(issuer.publicKey);
	} catch {
		return false;
	}
};

/** Is `cert` signed by any trusted root? Fast path: roots whose subject DN == the
 *  cert's issuer DN, verified by signature. Fallback: full scan (only if a DN
 *  formatting quirk made the exact-match miss — rare). */
function anchoredByRoot(cert: crypto.X509Certificate): boolean {
	const store = rootStore();
	const candidates = store.get(cert.issuer);
	if (candidates && candidates.some((r) => signedBy(cert, r))) return true;
	for (const list of store.values()) for (const r of list) if (signedBy(cert, r)) return true;
	return false;
}

// Cache of chains whose path-building already succeeded, keyed by the leaf cert's
// exact bytes → the chain's earliest notAfter (ms). A repeat handshake to the same
// server (same cert) then skips the expensive anchor scan; the hostname and expiry
// are still checked every call, and a rotated cert (new bytes) misses the cache.
const chainCache = new Map<string, number>();

/** Match the leaf against the requested host — by IP SAN for an IP literal, by DNS SAN
 *  otherwise. `checkHost` does not match IP addresses, so an IP target needs `checkIP`. */
function matchesHost(leaf: crypto.X509Certificate, host: string): boolean {
	const h = host.replace(/^\[|\]$/g, ''); // strip IPv6 brackets
	if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.includes(':')) return !!leaf.checkIP(h);
	return !!leaf.checkHost(host);
}

export function verifyChain(certsDer: Uint8Array[], host: string, now = new Date()): void {
	if (certsDer.length === 0) throw new Error('server sent no certificate');
	const leaf = new crypto.X509Certificate(Buffer.from(certsDer[0]!));
	if (!matchesHost(leaf, host)) throw new Error(`certificate is not for ${host} (subject ${leaf.subject})`);
	const key = crypto.createHash('sha256').update(Buffer.from(certsDer[0]!)).digest('hex');
	const cachedUntil = chainCache.get(key);
	if (cachedUntil !== undefined) {
		if (cachedUntil < now.getTime()) throw new Error(`certificate expired: ${leaf.subject}`);
		return; // already path-built for these exact bytes; host + expiry checked above
	}
	const chain = certsDer.map((d) => new crypto.X509Certificate(Buffer.from(d)));
	// Path building (like browsers): anchor at the EARLIEST chain cert a trusted
	// root vouches for — servers often append a legacy cross-signed root on top
	// (GlobalSign R1, AAA Certificate Services) whose own issuer isn't trusted.
	let anchor = -1;
	for (let i = 0; i < chain.length; i++) {
		if (anchoredByRoot(chain[i]!)) {
			anchor = i;
			break;
		}
	}
	if (anchor < 0) throw new Error(`untrusted: no chain cert is signed by a known root (top issuer "${chain[chain.length - 1]!.issuer}")`);
	// Validity + adjacent links only up to the anchor (certs above it don't matter).
	let validUntil = Infinity;
	for (let i = 0; i <= anchor; i++) {
		const c = chain[i]!;
		const to = new Date(c.validTo).getTime();
		if (to < now.getTime()) throw new Error(`certificate expired: ${c.subject}`);
		if (new Date(c.validFrom) > now) throw new Error(`certificate not yet valid: ${c.subject}`);
		if (i < anchor) {
			const issuer = chain[i + 1]!;
			// The signing cert MUST be a CA (basicConstraints CA:TRUE). Without this an
			// attacker can sign a leaf with any non-CA cert they hold and have it accepted.
			if (!issuer.ca) throw new Error(`untrusted: issuer is not a CA certificate (${issuer.subject})`);
			if (!signedBy(c, issuer)) throw new Error(`broken chain: ${c.subject} not signed by the next cert`);
		}
		validUntil = Math.min(validUntil, to);
	}
	chainCache.set(key, validUntil);
}

export type OcspMode = 'off' | 'soft' | 'hard';

/**
 * OCSP revocation check (RFC 6960). `staple` is the response the server sent in the
 * Certificate message (null if none). In 'soft' mode a missing/unknown status is
 * tolerated (what browsers do); in 'hard' mode a good, in-date response is required.
 * A confirmed `revoked` always throws, in either mode. On 'hard' with no staple we
 * fall back to the leaf's AIA responder over HTTP.
 *
 * certsDer[0] = leaf, certsDer[1] = its issuer (needed to key the CertID). Call only on
 * a full (non-resumed) handshake, after verifyChain has established the chain is trusted.
 */
export async function checkRevocation(certsDer: Uint8Array[], staple: Uint8Array | null, mode: OcspMode): Promise<void> {
	if (mode === 'off') return;
	if (certsDer.length < 2) {
		if (mode === 'hard') throw new Error('OCSP: issuer certificate not sent, cannot check revocation');
		return; // soft: no issuer → nothing to key the request on
	}
	const leaf = new crypto.X509Certificate(Buffer.from(certsDer[0]!));
	const issuer = new crypto.X509Certificate(Buffer.from(certsDer[1]!));
	let response = staple;
	if (!response && mode === 'hard') response = await fetchOcsp(leaf, issuer);
	if (!response) {
		if (mode === 'hard') throw new Error('OCSP: no stapled response and the AIA fetch failed');
		return; // soft-fail, like browsers when the responder is unreachable
	}
	const status = verifyOcsp(response, leaf, issuer);
	if (status === 'revoked') throw new Error(`certificate revoked (OCSP): ${leaf.subject}`);
	if (status === 'unknown' && mode === 'hard') throw new Error('OCSP: responder returned status unknown for this certificate');
}

/** TLS sigalg → crypto.verify options. Shared by CertificateVerify (1.3) and
 *  ServerKeyExchange (1.2) signature checks. */
export function verifyOpts(alg: number, pub: crypto.KeyObject): { hash: string; key: crypto.VerifyKeyObjectInput } {
	switch (alg) {
		case 0x0403: return { hash: 'sha256', key: { key: pub, dsaEncoding: 'der' } };
		case 0x0503: return { hash: 'sha384', key: { key: pub, dsaEncoding: 'der' } };
		case 0x0603: return { hash: 'sha512', key: { key: pub, dsaEncoding: 'der' } };
		case 0x0804: return { hash: 'sha256', key: { key: pub, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST } };
		case 0x0805: return { hash: 'sha384', key: { key: pub, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST } };
		case 0x0806: return { hash: 'sha512', key: { key: pub, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST } };
		case 0x0401: return { hash: 'sha256', key: { key: pub, padding: crypto.constants.RSA_PKCS1_PADDING } };
		case 0x0501: return { hash: 'sha384', key: { key: pub, padding: crypto.constants.RSA_PKCS1_PADDING } };
		case 0x0601: return { hash: 'sha512', key: { key: pub, padding: crypto.constants.RSA_PKCS1_PADDING } };
		default: throw new Error('unsupported CertificateVerify sigalg: 0x' + alg.toString(16));
	}
}

const CV_CONTEXT = concat(new Uint8Array(64).fill(0x20), new Uint8Array(Buffer.from('TLS 1.3, server CertificateVerify')), Uint8Array.of(0));

/** CertificateVerify: signature over (64 spaces || label || 0x00 || Hash(transcript up to Certificate)). */
export function verifyCertificateVerify(
	leafDer: Uint8Array,
	alg: number,
	signature: Uint8Array,
	hash: HashAlg,
	transcriptBeforeCV: Uint8Array
): void {
	const leaf = new crypto.X509Certificate(Buffer.from(leafDer));
	const content = concat(CV_CONTEXT, sha(hash, transcriptBeforeCV));
	const { hash: h, key } = verifyOpts(alg, leaf.publicKey);
	if (!crypto.verify(h, Buffer.from(content), key, Buffer.from(signature)))
		throw new Error('CertificateVerify failed — server does not hold the cert private key (possible MITM)');
}
