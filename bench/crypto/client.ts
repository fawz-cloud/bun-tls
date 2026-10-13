// One bun-tls measurement process for bench/crypto/ab.ts. The first argument is the source
// root to import (this tree or a baseline copy), the rest are bench/compare's scenario args.
// Usage: bun bench/crypto/client.ts <srcRoot> <scenario> <url> <n> <warm> <arg> <verify>
const root = process.argv.splice(2, 1)[0]!;
const { request, Session } = await import(`${root}/src/index.ts`);
const { main } = await import('../compare/common.mjs');

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
