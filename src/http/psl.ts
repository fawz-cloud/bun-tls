// Public Suffix List (publicsuffix.org) — to stop cookies being set on a registry
// suffix (e.g. Domain=.co.uk), the classic "supercookie" hole. Bundled dat file is
// parsed once into exact / wildcard / exception rule sets (algorithm per the PSL spec).
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const rules = new Set<string>(); // normal rules
const wildcards = new Set<string>(); // the part after "*." in a wildcard rule
const exceptions = new Set<string>(); // the part after "!" in an exception rule
let loaded = false;

function load(): void {
	if (loaded) return;
	loaded = true;
	const file = join(import.meta.dir, '..', '..', 'public_suffix_list.dat');
	if (!existsSync(file)) return; // no list → publicSuffix falls back to the last label
	for (const raw of readFileSync(file, 'utf8').split('\n')) {
		const line = raw.trim();
		if (!line || line.startsWith('//')) continue;
		if (line.startsWith('!')) exceptions.add(line.slice(1));
		else if (line.startsWith('*.')) wildcards.add(line.slice(2));
		else rules.add(line);
	}
}

/** The public suffix of `domain` (the registry-controlled part). */
export function publicSuffix(domain: string): string {
	load();
	const labels = domain.toLowerCase().replace(/\.$/, '').split('.');
	// exception rules win: the public suffix is the exception minus its first label
	for (let i = 0; i < labels.length; i++) {
		if (exceptions.has(labels.slice(i).join('.'))) return labels.slice(i + 1).join('.');
	}
	// otherwise the longest matching normal/wildcard rule (longest = smallest start index)
	for (let i = 0; i < labels.length; i++) {
		const cand = labels.slice(i).join('.');
		if (rules.has(cand)) return cand;
		if (wildcards.has(labels.slice(i + 1).join('.'))) return cand; // "*" matches labels[i]
	}
	return labels[labels.length - 1] ?? domain; // default rule "*": the TLD itself
}

/** True if `domain` is exactly a public suffix (cookies must not be set on one). */
export function isPublicSuffix(domain: string): boolean {
	return domain.toLowerCase().replace(/\.$/, '') === publicSuffix(domain);
}

/** The registrable domain (public suffix + one label), or null if `domain` is a suffix. */
export function registrableDomain(domain: string): string | null {
	const d = domain.toLowerCase().replace(/\.$/, '');
	const ps = publicSuffix(d);
	if (d === ps) return null;
	const labels = d.split('.');
	const n = ps.split('.').length + 1;
	return labels.slice(labels.length - n).join('.');
}
