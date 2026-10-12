// Public API for bun-tls. Import from here.
//   import { request, Session, presets, fromJa3 } from './scratch/bun-tls/src';
//   const r = await request({ url, fingerprint: presets.modern() });
export { request } from './http/client';
export type { RequestOptions, ClientResponse } from './http/client';
export { Session, CookieJar } from './http/session';
export type { SessionOptions } from './http/session';
export { PRESETS as presets, modern, dart, chrome131, firefox148 } from './fp/fingerprints';
export { clients, JA3 } from './fp/clients';
export { fromJa3, DEFAULT_SIGALGS } from './fp/ja3';
export type { FromJa3Opts } from './fp/ja3';
export type { Fingerprint } from './tls/clienthello';
export { buildClientHello, ja3FromClientHello, ja4FromClientHello } from './tls/clienthello';
export { TlsClient } from './tls/handshake';
export { tcpConnect, proxyConnect } from './tls/transport';
export type { Transport } from './tls/transport';
export * as ext from './tls/extensions';
export * as consts from './core/consts';
