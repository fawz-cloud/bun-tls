// X.509 path-validation constraints beyond "signed by a CA" (RFC 5280 §4.2): unknown
// critical extensions, Extended Key Usage on the leaf AND on every intermediate (EKU chaining,
// as browsers and OpenSSL enforce), basicConstraints pathLenConstraint, and NameConstraints
// over every certificate below the constraining CA — dNSName, iPAddress, rfc822Name (email),
// URI and directoryName. A constrained name form we cannot evaluate (otherName, x400Address,
// ediPartyName, registeredID) fails closed when a certificate carries such a name.
// node:crypto's X509Certificate does not expose these, so we parse them with the DER reader.
// verifyChain calls enforceConstraints.
import crypto from 'node:crypto';
import { der, children, oid } from './asn1';

const BASIC_CONSTRAINTS = '2.5.29.19';
const KEY_USAGE = '2.5.29.15';
const EKU = '2.5.29.37';
const SAN = '2.5.29.17';
const NAME_CONSTRAINTS = '2.5.29.30';
const SERVER_AUTH = '1.3.6.1.5.5.7.3.1';
const ANY_EKU = '2.5.29.37.0';
const EMAIL_ATTR = '1.2.840.113549.1.9.1'; // PKCS#9 emailAddress inside a subject DN
// Critical extensions we actually process — a critical extension outside this set must be
// rejected (RFC 5280 §4.2: a client that cannot process a critical extension must reject).
const PROCESSED = new Set([BASIC_CONSTRAINTS, KEY_USAGE, EKU, SAN, NAME_CONSTRAINTS]);
// GeneralName tags (RFC 5280 §4.2.1.6) we evaluate; any other form is "unsupported".
const GN_EMAIL = 0x81;
const GN_DNS = 0x82;
const GN_DIR = 0xa4;
const GN_URI = 0x86;
const GN_IP = 0x87;

interface Ext {
	oid: string;
	critical: boolean;
	value: Uint8Array; // the extnValue OCTET STRING content = the extension's own DER
}

/** TBSCertificate fields after the optional [0] version: serial, signature, issuer,
 *  validity, subject, subjectPublicKeyInfo, … */
function tbsFields(cert: crypto.X509Certificate) {
	const f = children(children(der(cert.raw).content)[0]!.content);
	return f[0]?.tag === 0xa0 ? f.slice(1) : f;
}

function extensions(cert: crypto.X509Certificate): Ext[] {
	const extField = tbsFields(cert).find((e) => e.tag === 0xa3); // [3] EXPLICIT Extensions
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

const text = (b: Uint8Array): string => Buffer.from(b).toString('latin1');
/** A Name as its RDNs (each the raw SET bytes), outermost first. */
const rdns = (nameContent: Uint8Array): Uint8Array[] => children(nameContent).map((r) => r.raw);

/** Names of one form-set: what a certificate carries, or what a constraint subtree lists. */
interface Names {
	dns: string[];
	ip: Uint8Array[];
	email: string[];
	uri: string[];
	dn: Uint8Array[][];
	other: Set<number>; // tags of name forms present that we do not evaluate
}
const noNames = (): Names => ({ dns: [], ip: [], email: [], uri: [], dn: [], other: new Set() });

function addName(n: Names, g: { tag: number; content: Uint8Array }): void {
	if (g.tag === GN_DNS) n.dns.push(text(g.content).toLowerCase());
	else if (g.tag === GN_IP) n.ip.push(g.content);
	else if (g.tag === GN_EMAIL) n.email.push(text(g.content));
	else if (g.tag === GN_URI) n.uri.push(text(g.content));
	else if (g.tag === GN_DIR) n.dn.push(rdns(der(g.content).content)); // [4] EXPLICIT Name
	else n.other.add(g.tag);
}

/** Every name NameConstraints apply to (RFC 5280 §4.2.1.10): the SAN entries plus the subject
 *  DN when non-empty — and, with no SAN at all, emailAddress attributes in the subject DN. */
function certNames(cert: crypto.X509Certificate): Names {
	const n = noNames();
	const subject = tbsFields(cert)[4]!;
	const subj = rdns(subject.content);
	if (subj.length) n.dn.push(subj);
	const san = extensions(cert).find((e) => e.oid === SAN);
	if (san) for (const g of children(der(san.value).content)) addName(n, g);
	else
		for (const rdn of children(subject.content))
			for (const atv of children(rdn.content)) {
				const [t, v] = children(atv.content);
				if (t && v && oid(t.content) === EMAIL_ATTR) n.email.push(text(v.content));
			}
	return n;
}

/** DNS: constraint is a suffix on a label boundary (empty matches everything; "example.com"
 *  matches "example.com" and any subdomain). */
function dnsInSubtree(name: string, constraint: string): boolean {
	const c = constraint.replace(/^\./, '').toLowerCase();
	if (c === '') return true;
	return name === c || name.endsWith('.' + c);
}

/** IP: constraint = address || mask (4+4 for v4, 16+16 for v6). */
function ipInSubtree(ip: Uint8Array, constraint: Uint8Array): boolean {
	const n = constraint.length / 2;
	if (ip.length !== n) return false;
	for (let i = 0; i < n; i++) if ((ip[i]! & constraint[n + i]!) !== (constraint[i]! & constraint[n + i]!)) return false;
	return true;
}

/** rfc822Name: "local@host" = that mailbox, "host" = any mailbox on that host, ".domain" = any
 *  mailbox on a host inside the domain. Hosts compare case-insensitively. */
function emailInSubtree(mail: string, c: string): boolean {
	const at = mail.lastIndexOf('@');
	if (at < 0) return false; // not a mailbox: inside no subtree
	const local = mail.slice(0, at);
	const host = mail.slice(at + 1).toLowerCase();
	const cat = c.lastIndexOf('@');
	if (cat >= 0) return local === c.slice(0, cat) && host === c.slice(cat + 1).toLowerCase();
	const ch = c.toLowerCase();
	return ch.startsWith('.') ? host.endsWith(ch) : host === ch;
}

/** URI: the constraint names the host ("example.com" = exactly that host, ".example.com" =
 *  any host inside the domain). A URI without a host is inside no subtree. */
function uriInSubtree(uri: string, c: string): boolean {
	let host: string;
	try {
		host = new URL(uri).hostname.toLowerCase();
	} catch {
		return false;
	}
	const ch = c.toLowerCase();
	return host !== '' && (ch.startsWith('.') ? host.endsWith(ch) : host === ch);
}

/** directoryName: the constraint's RDNs are a prefix of the name's (byte-equal RDNs — a
 *  differently encoded but equivalent name fails closed). */
const dnInSubtree = (name: Uint8Array[], c: Uint8Array[]): boolean => c.length <= name.length && c.every((rdn, i) => Buffer.compare(Buffer.from(rdn), Buffer.from(name[i]!)) === 0);

interface NameConstraints {
	permitted: Names;
	excluded: Names;
}
function parseNameConstraints(value: Uint8Array): NameConstraints {
	const nc: NameConstraints = { permitted: noNames(), excluded: noNames() };
	for (const sub of children(der(value).content)) {
		// permittedSubtrees [0] (0xa0), excludedSubtrees [1] (0xa1); each = SEQ OF GeneralSubtree.
		if (sub.tag !== 0xa0 && sub.tag !== 0xa1) continue;
		const into = sub.tag === 0xa0 ? nc.permitted : nc.excluded;
		for (const gs of children(sub.content)) addName(into, children(gs.content)[0]!); // GeneralSubtree.base
	}
	return nc;
}

function within<T>(form: string, names: T[], permitted: T[], excluded: T[], inTree: (n: T, c: T) => boolean, show: (n: T) => string): void {
	for (const n of names) {
		if (excluded.some((c) => inTree(n, c))) throw new Error(`certificate ${form} ${show(n)} is in an excluded NameConstraints subtree`);
		if (permitted.length && !permitted.some((c) => inTree(n, c))) throw new Error(`certificate ${form} ${show(n)} is not in any permitted NameConstraints subtree`);
	}
}

function applyNameConstraints(nc: NameConstraints, n: Names): void {
	const { permitted: p, excluded: x } = nc;
	within('DNS name', n.dns, p.dns, x.dns, dnsInSubtree, (d) => d);
	within('IP address', n.ip, p.ip, x.ip, ipInSubtree, (a) => Buffer.from(a).toString('hex'));
	within('email', n.email, p.email, x.email, emailInSubtree, (e) => e);
	within('URI', n.uri, p.uri, x.uri, uriInSubtree, (u) => u);
	within('directory name', n.dn, p.dn, x.dn, dnInSubtree, () => '(subject)');
	for (const tag of n.other)
		if (p.other.has(tag) || x.other.has(tag)) throw new Error(`NameConstraints constrain a name form we cannot check (tag 0x${tag.toString(16)}) — rejected`);
}

/** EKU, when present, must allow serverAuth (or anyExtendedKeyUsage). */
function checkEku(exts: Ext[], what: string): void {
	const eku = exts.find((e) => e.oid === EKU);
	if (!eku) return;
	const purposes = children(der(eku.value).content).map((o) => oid(o.content));
	if (!purposes.includes(SERVER_AUTH) && !purposes.includes(ANY_EKU)) throw new Error(`${what} EKU does not permit serverAuth (${purposes.join(', ')})`);
}

/**
 * Enforce path-validation constraints over a built chain (leaf = chain[0] up to the cert
 * just below the trusted anchor at index `anchor`). Throws on any violation:
 *  - a critical extension we do not process (on any cert),
 *  - an EKU (leaf or intermediate) that does not permit serverAuth,
 *  - a CA's pathLenConstraint exceeded,
 *  - a name of any certificate below a CA outside that CA's NameConstraints. Self-issued
 *    intermediates are exempt, as RFC 5280 §6.1.3 says; the leaf never is.
 */
export function enforceConstraints(chain: crypto.X509Certificate[], anchor: number): void {
	const names: Names[] = [];
	const namesOf = (j: number) => (names[j] ??= certNames(chain[j]!));

	for (let i = 0; i <= anchor; i++) {
		const cert = chain[i]!;
		const exts = extensions(cert);
		for (const e of exts) if (e.critical && !PROCESSED.has(e.oid)) throw new Error(`unhandled critical certificate extension ${e.oid} (${cert.subject})`);
		checkEku(exts, i === 0 ? 'leaf certificate' : `intermediate certificate (${cert.subject})`);
		if (i === 0) continue;

		// CA cert: pathLenConstraint limits the number of non-self-issued CAs below it.
		const bc = exts.find((e) => e.oid === BASIC_CONSTRAINTS);
		if (bc) {
			const pathLen = children(der(bc.value).content).find((p) => p.tag === 0x02); // INTEGER pathLenConstraint
			if (pathLen) {
				const max = pathLen.content.reduce((a, b) => a * 256 + b, 0);
				const below = i - 1; // intermediate CAs between this CA and the leaf
				if (below > max) throw new Error(`pathLenConstraint ${max} exceeded (${below} CAs below ${cert.subject})`);
			}
		}
		// NameConstraints on this CA bind every certificate below it.
		const ncExt = exts.find((e) => e.oid === NAME_CONSTRAINTS);
		if (ncExt) {
			const nc = parseNameConstraints(ncExt.value);
			for (let j = 0; j < i; j++) if (j === 0 || chain[j]!.subject !== chain[j]!.issuer) applyNameConstraints(nc, namesOf(j));
		}
	}
}

// Self-check: subtree matching per name form. Run: bun src/tls/x509.ts
if (import.meta.main) {
	const ok = (c: boolean, m: string) => {
		if (!c) throw new Error('x509 self-check failed: ' + m);
	};
	ok(dnsInSubtree('host.example.com', 'example.com') && !dnsInSubtree('evil.com', 'example.com'), 'dns');
	ok(emailInSubtree('a@example.com', 'example.com') && !emailInSubtree('a@sub.example.com', 'example.com'), 'email host');
	ok(emailInSubtree('a@sub.example.com', '.example.com') && !emailInSubtree('a@example.com', '.example.com'), 'email domain');
	ok(emailInSubtree('a@EXAMPLE.com', 'a@example.com') && !emailInSubtree('b@example.com', 'a@example.com'), 'email mailbox');
	ok(uriInSubtree('https://x.example.com/p', '.example.com') && !uriInSubtree('https://evil.com/', '.example.com') && !uriInSubtree('urn:x', 'example.com'), 'uri');
	let threw = false;
	try {
		const n = noNames();
		n.other.add(0xa0);
		const nc = { permitted: noNames(), excluded: noNames() };
		nc.permitted.other.add(0xa0);
		applyNameConstraints(nc, n);
	} catch {
		threw = true;
	}
	ok(threw, 'unsupported constrained form fails closed');
	console.log('x509 constraints self-check ok');
}
