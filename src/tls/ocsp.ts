// OCSP (RFC 6960): verify a stapled OCSP response, and — when none is stapled —
// fetch one from the certificate's AIA responder over plain HTTP. We verify the
// responder signature (by the issuer, or by a delegate the issuer signed with the
// OCSPSigning EKU), bind the response to our leaf via CertID, and check freshness.
import crypto from 'node:crypto';
import { der, children, oid, derTime, seq, octet, tlv } from './asn1';

const OID_BASIC = '1.3.6.1.5.5.7.48.1.1'; // id-pkix-ocsp-basic (responseType)
const OID_AD_OCSP = '1.3.6.1.5.5.7.48.1'; // id-ad-ocsp (AIA access method)
const OID_AIA = '1.3.6.1.5.5.7.1.1'; // Authority Information Access extension
const OID_EKU = '2.5.29.37'; // extendedKeyUsage extension
const OID_OCSP_SIGNING = '1.3.6.1.5.5.7.3.9'; // id-kp-OCSPSigning
// CertID hashAlgorithm → node hash name. OCSP keys CertID by SHA-1 in practice.
const HASH: Record<string, string> = {
	'1.3.14.3.2.26': 'sha1',
	'2.16.840.1.101.3.4.2.1': 'sha256',
	'2.16.840.1.101.3.4.2.2': 'sha384',
	'2.16.840.1.101.3.4.2.3': 'sha512'
};
// signatureAlgorithm OID → { hash, ec? }. Covers RSA PKCS#1 v1.5 + ECDSA (what CAs use
// for OCSP). RSA-PSS is not handled (rare for OCSP) — verify throws on it.
const SIG: Record<string, { hash: string; ec?: boolean }> = {
	'1.2.840.113549.1.1.11': { hash: 'sha256' },
	'1.2.840.113549.1.1.12': { hash: 'sha384' },
	'1.2.840.113549.1.1.13': { hash: 'sha512' },
	'1.2.840.10045.4.3.2': { hash: 'sha256', ec: true },
	'1.2.840.10045.4.3.3': { hash: 'sha384', ec: true },
	'1.2.840.10045.4.3.4': { hash: 'sha512', ec: true }
};
// DER of AlgorithmIdentifier { sha1, NULL } — the CertID hash algo for our requests.
const SHA1_ALG = Uint8Array.of(0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00);

export type OcspStatus = 'good' | 'revoked' | 'unknown';

const eq = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && Buffer.compare(a, b) === 0;
const tbsChildren = (cert: crypto.X509Certificate): ReturnType<typeof children> => children(children(der(cert.raw).content)[0]!.content);
/** Index of the subject Name among tbsCertificate children (skips optional [0] version). */
const subjectIdx = (tbs: ReturnType<typeof children>): number => (tbs[0]!.tag === 0xa0 ? 1 : 0) + 4;

/** Issuer identifiers for a CertID: its subject-DN DER and its raw public-key bytes. */
function issuerIds(issuer: crypto.X509Certificate): { subjectDer: Uint8Array; keyBytes: Uint8Array } {
	const tbs = tbsChildren(issuer);
	const subjectDer = tbs[subjectIdx(tbs)]!.raw;
	const spki = new Uint8Array(issuer.publicKey.export({ type: 'spki', format: 'der' }) as Buffer);
	const bit = children(der(spki).content)[1]!; // subjectPublicKey BIT STRING
	return { subjectDer, keyBytes: bit.content.subarray(1) }; // drop the unused-bits count byte
}

const safeVerify = (cert: crypto.X509Certificate, key: crypto.KeyObject): boolean => {
	try {
		return cert.verify(key);
	} catch {
		return false;
	}
};

/** Does `cert` carry the OCSPSigning EKU (required of a delegated responder)? */
function hasOcspSigningEku(cert: crypto.X509Certificate): boolean {
	const ext = tbsChildren(cert).find((e) => e.tag === 0xa3); // [3] EXPLICIT extensions
	if (!ext) return false;
	for (const e of children(children(ext.content)[0]!.content)) {
		const f = children(e.content);
		if (oid(f[0]!.content) !== OID_EKU) continue;
		for (const o of children(der(f[f.length - 1]!.content).content)) if (oid(o.content) === OID_OCSP_SIGNING) return true;
	}
	return false;
}

/**
 * Verify an OCSP response (DER) for `leaf` issued by `issuer`. Returns the leaf's
 * revocation status. Throws if the response is malformed, the signature is invalid,
 * it is not bound to this certificate (CertID), or it is stale.
 */
export function verifyOcsp(ocspDer: Uint8Array, leaf: crypto.X509Certificate, issuer: crypto.X509Certificate, now = Date.now()): OcspStatus {
	const resp = children(der(ocspDer).content);
	if (resp[0]!.content[0] !== 0) throw new Error('OCSP responseStatus=' + resp[0]!.content[0]);
	const respBytes = children(resp[1]!.content)[0]!; // [0] EXPLICIT ResponseBytes
	const rb = children(respBytes.content);
	if (oid(rb[0]!.content) !== OID_BASIC) throw new Error('OCSP non-basic responseType');
	const basic = children(der(rb[1]!.content).content); // response OCTET STRING → BasicOCSPResponse
	const tbs = basic[0]!; // ResponseData (raw bytes are what the signature covers)
	const sig = basic[2]!.content.subarray(1); // signature BIT STRING, drop unused-bits byte
	const sa = SIG[oid(children(basic[1]!.content)[0]!.content)];
	if (!sa) throw new Error('OCSP unsupported signature algorithm');

	// Responder = the issuer itself, or a delegate the issuer signed carrying the
	// OCSPSigning EKU. Try each authorised key; signature must verify under one.
	const keys: crypto.KeyObject[] = [];
	const certsField = basic.find((e) => e.tag === 0xa0); // [0] EXPLICIT certs
	if (certsField) {
		const first = children(certsField.content)[0];
		if (first) {
			const delegate = new crypto.X509Certificate(Buffer.from(first.raw));
			if (safeVerify(delegate, issuer.publicKey) && hasOcspSigningEku(delegate)) keys.push(delegate.publicKey);
		}
	}
	keys.push(issuer.publicKey);
	const verified = keys.some((k) => {
		try {
			return crypto.verify(sa.hash, Buffer.from(tbs.raw), sa.ec ? { key: k, dsaEncoding: 'der' } : k, Buffer.from(sig));
		} catch {
			return false;
		}
	});
	if (!verified) throw new Error('OCSP signature invalid (not signed by the issuer or an authorised responder)');

	// Find the SingleResponse whose CertID matches our leaf.
	const { subjectDer, keyBytes } = issuerIds(issuer);
	const leafSerial = leaf.serialNumber.replace(/^0+/, '').toUpperCase();
	const responses = children(children(tbs.content).find((e) => e.tag === 0x30)!.content); // SEQ OF SingleResponse
	for (const srRaw of responses) {
		const sr = children(srRaw.content);
		const cid = children(sr[0]!.content); // hashAlg, issuerNameHash, issuerKeyHash, serial
		const hashName = HASH[oid(children(cid[0]!.content)[0]!.content)];
		if (!hashName) continue;
		if (!eq(cid[1]!.content, crypto.createHash(hashName).update(subjectDer).digest())) continue;
		if (!eq(cid[2]!.content, crypto.createHash(hashName).update(keyBytes).digest())) continue;
		if (Buffer.from(cid[3]!.content).toString('hex').replace(/^0+/, '').toUpperCase() !== leafSerial) continue;

		// Freshness: thisUpdate ≤ now ≤ nextUpdate (±5 min skew).
		const SKEW = 5 * 60_000;
		const after2 = sr.slice(2);
		const thisUpd = derTime(after2.find((e) => e.tag === 0x18 || e.tag === 0x17)!.content);
		const nextEl = after2.find((e) => e.tag === 0xa0); // [0] EXPLICIT nextUpdate
		const nextUpd = nextEl ? derTime(children(nextEl.content)[0]!.content) : null;
		if (thisUpd - SKEW > now) throw new Error('OCSP response not yet valid (thisUpdate in the future)');
		if (nextUpd != null && nextUpd + SKEW < now) throw new Error('OCSP response expired (nextUpdate in the past)');

		const t = sr[1]!.tag; // CertStatus: [0] good, [1] revoked, [2] unknown
		return t === 0x80 ? 'good' : t === 0xa1 ? 'revoked' : 'unknown';
	}
	throw new Error('OCSP response has no entry for this certificate (CertID mismatch)');
}

/** The leaf's OCSP responder URL from its AIA extension, or null. */
export function ocspUrl(leaf: crypto.X509Certificate): string | null {
	const ext = tbsChildren(leaf).find((e) => e.tag === 0xa3);
	if (!ext) return null;
	for (const e of children(children(ext.content)[0]!.content)) {
		const f = children(e.content);
		if (oid(f[0]!.content) !== OID_AIA) continue;
		for (const ad of children(der(f[f.length - 1]!.content).content)) {
			const p = children(ad.content);
			if (oid(p[0]!.content) === OID_AD_OCSP) return Buffer.from(p[1]!.content).toString('latin1'); // [6] IA5String URL
		}
	}
	return null;
}

/** Build a DER OCSPRequest for `leaf` under `issuer` (single CertID, SHA-1). */
function ocspRequest(leaf: crypto.X509Certificate, issuer: crypto.X509Certificate): Uint8Array {
	const { subjectDer, keyBytes } = issuerIds(issuer);
	const tbs = tbsChildren(leaf);
	const serial = tbs[tbs[0]!.tag === 0xa0 ? 1 : 0]!.raw; // serialNumber INTEGER (verbatim, keeps sign byte)
	const certID = seq(SHA1_ALG, octet(crypto.createHash('sha1').update(subjectDer).digest()), octet(crypto.createHash('sha1').update(keyBytes).digest()), serial);
	return seq(seq(seq(seq(certID)))); // OCSPRequest{ TBSRequest{ requestList{ Request{ CertID }}}}
}

/** Fetch an OCSP response from the leaf's AIA responder (plain HTTP POST). null on any
 *  failure — the caller decides soft-fail vs hard-fail. Uses Bun's global fetch (the
 *  responder is a CA endpoint, not the fingerprinted target, so no custom TLS needed). */
export async function fetchOcsp(leaf: crypto.X509Certificate, issuer: crypto.X509Certificate, timeoutMs = 5000): Promise<Uint8Array | null> {
	const url = ocspUrl(leaf);
	if (!url) return null;
	try {
		const res = await fetch(url, {
			method: 'POST',
			headers: { 'Content-Type': 'application/ocsp-request', Accept: 'application/ocsp-response' },
			body: ocspRequest(leaf, issuer),
			signal: AbortSignal.timeout(timeoutMs)
		});
		if (!res.ok) return null;
		return new Uint8Array(await res.arrayBuffer());
	} catch {
		return null;
	}
}

// Self-check: tlv/seq length encoding round-trips through the reader. Run: bun src/tls/ocsp.ts
if (import.meta.main) {
	const big = new Uint8Array(300).fill(0xab);
	const e = seq(octet(big));
	const outer = der(e);
	const inner = children(outer.content)[0]!;
	if (outer.tag !== 0x30 || inner.tag !== 0x04 || !eq(inner.content, big)) throw new Error('DER encode/parse self-check failed');
	console.log('asn1 encode/parse ok (len', e.length, ')');
}
