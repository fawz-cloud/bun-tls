// TLS 1.2 fallback: our ClientHello offers TLS 1.3 + 1.2 (as every browser does); a 1.2-only
// server answers in 1.2 and the handshake finishes as 1.2 on the same connection — unless the
// server random carries the RFC 8446 §4.1.3 downgrade marker. Run: bun test/tls12.test.ts
import assert from 'node:assert';
import { existsSync, readFileSync } from 'node:fs';
import tls from 'node:tls';
import { concat } from '../src/core/bytes';
import { TlsClient, Negotiated12 } from '../src/tls/handshake';
import { modern } from '../src/fp/fingerprints';
import { request } from '../src/index';

/** A TLS 1.2 ServerHello record (ECDHE-RSA-AES128-GCM, extended_master_secret). */
function serverHello12(random: Uint8Array): Uint8Array {
	const exts = Uint8Array.of(0x00, 0x17, 0x00, 0x00);
	const body = concat(Uint8Array.of(0x03, 0x03), random, Uint8Array.of(32), new Uint8Array(32), Uint8Array.of(0xc0, 0x2f, 0x00, 0x00, exts.length), exts);
	const hs = concat(Uint8Array.of(2, 0, body.length >> 8, body.length & 0xff), body);
	return concat(Uint8Array.of(0x16, 0x03, 0x03, hs.length >> 8, hs.length & 0xff), hs);
}
/** A transport that swallows our writes and answers with one record. */
const replay = (record: Uint8Array) => {
	let done = false;
	return { write() {}, async writeAsync() {}, read: async () => (done ? null : ((done = true), record)), close() {} };
};
const handshakeWith = (random: Uint8Array) => new TlsClient(replay(serverHello12(random)) as never, { host: 'x', fingerprint: modern(), verify: false }).handshake();

// The downgrade marker in a 1.2 ServerHello means 1.3 was stripped in transit: abort.
const marked = crypto.getRandomValues(new Uint8Array(32));
marked.set(Buffer.from('444f574e47524401', 'hex'), 24); // "DOWNGRD\x01"
await assert.rejects(handshakeWith(marked), /downgrade/, 'DOWNGRD marker aborts the handshake');
// Without it, the 1.3 client hands the connection over to finish as TLS 1.2.
await assert.rejects(handshakeWith(crypto.getRandomValues(new Uint8Array(32))), (e: unknown) => e instanceof Negotiated12, 'a plain 1.2 ServerHello hands over');

const dir = new URL('../bench', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
if (!existsSync(`${dir}/cert.pem`) || !existsSync(`${dir}/key.pem`)) {
	console.log('tls12: OK (local-server cases SKIPPED — no bench/cert.pem)');
	process.exit(0);
}

// A real TLS 1.2-only server: every preset reaches it, over TLS 1.2.
const srv = tls.createServer({ key: readFileSync(`${dir}/key.pem`), cert: readFileSync(`${dir}/cert.pem`), maxVersion: 'TLSv1.2' }, (s) => {
	s.on('error', () => {});
	s.on('data', () => s.end(`HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\n${s.getProtocol()}`));
});
await new Promise<void>((r) => srv.listen(0, r));
const url = `https://localhost:${(srv.address() as { port: number }).port}/`;
for (const [name, o] of [['default', {}], ['chrome', { persona: 'chrome' }], ['firefox', { persona: 'firefox', http2: false }], ['safari', { persona: 'safari', http2: false }]] as const) {
	const r = await request({ url, verify: false, timeoutMs: 5000, ...o });
	assert.equal(r.status, 200, `${name}: 200`);
	assert.equal(r.text(), 'TLSv1.2', `${name}: negotiated TLS 1.2`);
}
srv.close();

console.log('tls12: OK');
