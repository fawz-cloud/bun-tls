// bun-tls side of bench/compare: persona 'chrome' over HTTP/1.1 keep-alive.
import { request, Session } from '../../src';
import { main } from './common.mjs';

// http2:false — the chrome persona defaults to h2 and the bench server is HTTP/1.1-only.
const opts = { persona: 'chrome', http2: false, verify: process.argv[7] === '1' };

await main({
	fresh: async (url: string) => (await request({ url, ...opts })).body.length,
	session: () => {
		const s = new Session(opts);
		return {
			get: async (u: string) => (await s.get(u)).body.length,
			post: async (u: string, body: Uint8Array) => (await s.post(u, { body })).body.length,
			close: () => s.close()
		};
	}
});
