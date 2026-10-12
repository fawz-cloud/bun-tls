// Ready-made client fingerprints.
//
// Two tiers:
//  1. Spec presets (chrome, edge, firefox, dart): built from a ClientHello spec —
//     utls u_parrots.go for the browsers, a live capture for dart:io. Their JA3/JA3N
//     match the published values for those versions (verified against an echo
//     server). See fingerprints.ts for what still differs from the real client
//     (key_share, ALPN, TLS version list).
//  2. Reference presets (safari, okhttp): rebuilt from a reference JA3 string via
//     fromJa3. A JA3 only summarizes part of a ClientHello (version, ciphers, extension
//     types, curves, point formats), so these match that JA3 and nothing more.
//
// fromJa3(targetJa3) reproduces any JA3 the same way, with the same limits.
// This client speaks HTTP/1.1 only, so presets advertise ALPN http/1.1.
import type { Fingerprint } from '../tls/clienthello';
import { fromJa3 } from './ja3';
import { dart, chrome131, firefox148, CHROME_SIGALGS } from './fingerprints';
import { Group } from '../core/consts';

/** Reference JA3 strings for the fromJa3-based presets (point-in-time; clients
 *  rotate). The spec presets do NOT use these — they are built from a full
 *  ClientHello spec, not from a JA3 string. */
export const JA3: Record<string, string> = {
	safari:
		'771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47,0-23-65281-10-11-16-5-13-18-51-45-43,29-23-24-25,0',
	okhttp:
		'771,4865-4866-4867-49195-49196-52393-49199-49200-52392-49161-49162-49171-49172-156-157-47-53,0-23-65281-10-11-16-13-43-45-51,29-23-24,0'
};

const browser = (ja3: string, sigAlgs = CHROME_SIGALGS): Fingerprint =>
	fromJa3(ja3, { grease: true, alpn: ['http/1.1'], sigAlgs, keyShareGroups: [Group.x25519] });

/** Named client fingerprints. `chrome`/`edge`/`firefox`/`dart` are spec presets
 *  (JA3/JA3N match the published values); `safari`/`okhttp` are JA3 rebuilds. */
export const clients: Record<string, () => Fingerprint> = {
	dart,
	chrome: chrome131,
	edge: chrome131, // Edge 131 is Chromium — same TLS stack as Chrome 131
	firefox: firefox148,
	safari: () => browser(JA3.safari!),
	okhttp: () => browser(JA3.okhttp!)
};
