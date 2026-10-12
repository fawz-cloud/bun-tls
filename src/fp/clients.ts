// Ready-made client fingerprints.
//
// Two tiers:
//  1. Faithful presets (chrome, edge, firefox, dart) — transcribed byte-for-byte
//     from authoritative sources (utls u_parrots.go for the browsers; a live
//     capture for dart). Their JA3/JA3N match the real client, including the
//     post-quantum X25519MLKEM768 group and GREASE ECH.
//  2. Reference presets (safari, okhttp) — rebuilt from a reference JA3 string via
//     fromJa3 (hash-exact to that JA3; GREASE added). Capture your own for an exact
//     current version the way scratch/bun-tls/capture.dart captured dart:io.
//
// Universal escape hatch for ANY client: fromJa3(targetJa3).
//
// h1 caveat: this client speaks HTTP/1.1 only, so browser presets advertise ALPN
// http/1.1 (the ALPN value is not in JA3 → the JA3 hash still matches; a WAF keying
// on JA3 is satisfied). True h2 impersonation needs an h2 stack (not built).
import type { Fingerprint } from '../tls/clienthello';
import { fromJa3 } from './ja3';
import { dart, chrome131, firefox148, CHROME_SIGALGS } from './fingerprints';
import { Group } from '../core/consts';

/** Reference JA3 strings for the fromJa3-based presets (point-in-time; browsers
 *  rotate). The faithful presets above do NOT use these — they are built from the
 *  real ClientHello structure, not from a JA3 string. */
export const JA3: Record<string, string> = {
	safari:
		'771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47,0-23-65281-10-11-16-5-13-18-51-45-43,29-23-24-25,0',
	okhttp:
		'771,4865-4866-4867-49195-49196-52393-49199-49200-52392-49161-49162-49171-49172-156-157-47-53,0-23-65281-10-11-16-13-43-45-51,29-23-24,0'
};

const browser = (ja3: string, sigAlgs = CHROME_SIGALGS): Fingerprint =>
	fromJa3(ja3, { grease: true, alpn: ['http/1.1'], sigAlgs, keyShareGroups: [Group.x25519] });

/** Named client fingerprints. `chrome`/`edge`/`firefox`/`dart` are faithful
 *  (byte-exact to the real client); `safari`/`okhttp` are reference-JA3 rebuilds. */
export const clients: Record<string, () => Fingerprint> = {
	dart,
	chrome: chrome131,
	edge: chrome131, // Edge 131 is Chromium — same TLS stack as Chrome 131
	firefox: firefox148,
	safari: () => browser(JA3.safari!),
	okhttp: () => browser(JA3.okhttp!)
};
