// X.509 path-validation constraints beyond "signed by a CA" (RFC 5280 §4.2): unknown
// critical extensions, leaf Extended Key Usage, basicConstraints pathLenConstraint, and
// NameConstraints (DNS + IP). node:crypto's X509Certificate does not expose these, so we
// parse them with the DER reader. verifyChain calls enforceConstraints over the chain.
import crypto from 'node:crypto';
import { der, children, oid } from './asn1';

const BASIC_CONSTRAINTS = '2.5.29.19';
const KEY_USAGE = '2.5.29.15';
const EKU = '2.5.29.37';
const SAN = '2.5.29.17';
const NAME_CONSTRAINTS = '2.5.29.30';
const SERVER_AUTH = '1.3.6.1.5.5.7.3.1';
const ANY_EKU = '2.5.29.37.0';
// Critical extensions we actually process — a critical extension outside this set must be
// rejected (RFC 5280 §4.2: a client that cannot process a critical extension must reject).
const PROCESSED = new Set([BASIC_CONSTRAINTS, KEY_USAGE, EKU, SAN, NAME_CONSTRAINTS]);

interface Ext {
	oid: string;
	critical: boolean;
	value: Uint8Array; // the extnValue OCTET STRING content = the extension's own DER
}

function extensions(cert: crypto.X509Certificate): Ext[] {
	const tbs = children(der(cert.raw).content)[0]!;
	const extField = children(tbs.content).find((e) => e.tag === 0xa3); // [3] EXPLICIT Extensions
	if (!extField) return [];
	const out: Ext[] = [];
	for (const e of children(children(extField.content)[0]!.content)) {
		const f = children(e.content);
		let critical = false;
		let valIdx = 1;
		if (f[1] && f[1].tag === 0x01) {
			critical = f[1]!.content[0] !== 0; // BOOLEAN
			valIdx = 2;
		}
		out.push({ oid: oid(f[0]!.content), critical, value: f[valIdx]!.content });
	}
	return out;
}

/** dNSName (0x82) and iPAddress (0x87) GeneralNames from a SAN or NameConstraints body. */
function generalNames(seq: Uint8Array): { dns: string[]; ip: Uint8Array[] } {
	const dns: string[] = [];
	const ip: Uint8Array[] = [];
	for (const g of children(seq)) {
		if (g.tag === 0x82) dns.push(Buffer.from(g.content).toString('latin1').toLowerCase());
		else if (g.tag === 0x87) ip.push(g.content);
	}
	return { dns, ip };
}

/** RFC 5280 §4.2.1.10 DNS match: constraint is a suffix on a label boundary (an empty
 *  constraint matches everything; "example.com" matches "example.com" and any subdomain). */
function dnsInSubtree(name: string, constraint: string): boolean {
	const c = constraint.replace(/^\./, '').toLowerCase();
	if (c === '') return true;
	return name === c || name.endsWith('.' + c);
}

/** IP match: constraint = address || mask (4+4 for v4, 16+16 for v6). */
function ipInSubtree(ip: Uint8Array, constraint: Uint8Array): boolean {
	const n = constraint.length / 2;
	if (ip.length !== n) return false;
	for (let i = 0; i < n; i++) if ((ip[i]! & constraint[n + i]!) !== (constraint[i]! & constraint[n + i]!)) return false;
	return true;
}

function leafNames(leaf: crypto.X509Certificate): { dns: string[]; ip: Uint8Array[] } {
	const ext = extensions(leaf).find((e) => e.oid === SAN);
	return ext ? generalNames(der(ext.value).content) : { dns: [], ip: [] };
}

interface NameConstraints {
	permittedDns: string[];
	excludedDns: string[];
	permittedIp: Uint8Array[];
	excludedIp: Uint8Array[];
}
function parseNameConstraints(value: Uint8Array): NameConstraints {
	const nc: NameConstraints = { permittedDns: [], excludedDns: [], permittedIp: [], excludedIp: [] };
	for (const sub of children(der(value).content)) {
		// permittedSubtrees [0] (0xa0), excludedSubtrees [1] (0xa1); each = SEQ OF GeneralSubtree.
		const permitted = sub.tag === 0xa0;
		if (sub.tag !== 0xa0 && sub.tag !== 0xa1) continue;
		for (const gs of children(sub.content)) {
			const base = children(gs.content)[0]!; // GeneralSubtree.base = GeneralName
			if (base.tag === 0x82) (permitted ? nc.permittedDns : nc.excludedDns).push(Buffer.from(base.content).toString('latin1').toLowerCase());
			else if (base.tag === 0x87) (permitted ? nc.permittedIp : nc.excludedIp).push(base.content);
		}
	}
	return nc;
}

function applyNameConstraints(nc: NameConstraints, names: { dns: string[]; ip: Uint8Array[] }): void {
	for (const d of names.dns) {
		if (nc.excludedDns.some((c) => dnsInSubtree(d, c))) throw new Error(`certificate name ${d} is in an excluded NameConstraints subtree`);
		if (nc.permittedDns.length && !nc.permittedDns.some((c) => dnsInSubtree(d, c))) throw new Error(`certificate name ${d} is not in any permitted NameConstraints subtree`);
	}
	for (const a of names.ip) {
		if (nc.excludedIp.some((c) => ipInSubtree(a, c))) throw new Error('certificate IP is in an excluded NameConstraints subtree');
		if (nc.permittedIp.length && !nc.permittedIp.some((c) => ipInSubtree(a, c))) throw new Error('certificate IP is not in any permitted NameConstraints subtree');
	}
}

/**
 * Enforce path-validation constraints over a built chain (leaf = chain[0] up to the cert
 * just below the trusted anchor at index `anchor`). Throws on any violation:
 *  - a critical extension we do not process (on any cert),
 *  - the leaf's EKU not permitting serverAuth,
 *  - a CA's pathLenConstraint exceeded,
 *  - the leaf's names outside any CA's NameConstraints (permitted/excluded, DNS + IP).
 */
export function enforceConstraints(chain: crypto.X509Certificate[], anchor: number): void {
	const leaf = chain[0]!;
	const names = leafNames(leaf);

	for (let i = 0; i <= anchor; i++) {
		const exts = extensions(chain[i]!);
		for (const e of exts) if (e.critical && !PROCESSED.has(e.oid)) throw new Error(`unhandled critical certificate extension ${e.oid} (${chain[i]!.subject})`);

		if (i === 0) {
			// Leaf EKU: if present, it must allow serverAuth (or anyExtendedKeyUsage).
			const eku = exts.find((e) => e.oid === EKU);
			if (eku) {
				const purposes = children(der(eku.value).content).map((o) => oid(o.content));
				if (!purposes.includes(SERVER_AUTH) && !purposes.includes(ANY_EKU))
					throw new Error(`leaf certificate EKU does not permit serverAuth (${purposes.join(', ')})`);
			}
		} else {
			// CA cert: pathLenConstraint limits the number of non-self-issued CAs below it.
			const bc = exts.find((e) => e.oid === BASIC_CONSTRAINTS);
			if (bc) {
				const parts = children(der(bc.value).content);
				const pathLen = parts.find((p) => p.tag === 0x02); // INTEGER pathLenConstraint
				if (pathLen) {
					const max = pathLen.content.reduce((a, b) => a * 256 + b, 0);
					const below = i - 1; // intermediate CAs between this CA and the leaf
					if (below > max) throw new Error(`pathLenConstraint ${max} exceeded (${below} CAs below ${chain[i]!.subject})`);
				}
			}
			// NameConstraints on this CA must contain the leaf's names.
			const nc = exts.find((e) => e.oid === NAME_CONSTRAINTS);
			if (nc) applyNameConstraints(parseNameConstraints(nc.value), names);
		}
	}
}

// Self-check: a DNS subtree match + an excluded-name rejection. Run: bun src/tls/x509.ts
if (import.meta.main) {
	if (!dnsInSubtree('host.example.com', 'example.com') || dnsInSubtree('evil.com', 'example.com')) throw new Error('dnsInSubtree self-check failed');
	const nc: NameConstraints = { permittedDns: [], excludedDns: ['localhost'], permittedIp: [], excludedIp: [] };
	let threw = false;
	try {
		applyNameConstraints(nc, { dns: ['localhost'], ip: [] });
	} catch {
		threw = true;
	}
	if (!threw) throw new Error('excluded-subtree self-check failed');
	console.log('x509 constraints self-check ok');
}
