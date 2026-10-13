// impers side of bench/compare: impersonate 'chrome' over HTTP/1.1. Runs on Node and Bun.
import { Session } from 'impers';
import { main } from './common.mjs';

const base = { impersonate: 'chrome', httpVersion: '1.1', verify: process.argv[7] === '1' };
// Own multi handle sized to the concurrency (the shared default caps a host at 6 connections);
// close() tears it down, so a fresh Session really means a fresh connection.
const session = (conc) => {
	const s = new Session({ ...base, maxConnections: conc, maxHostConnections: conc });
	return {
		get: async (u) => (await s.get(u)).content.length,
		post: async (u, body) => (await s.post(u, { content: body })).content.length,
		close: () => s.close()
	};
};

await main({
	fresh: async (u) => {
		const s = session(1);
		try {
			return await s.get(u);
		} finally {
			await s.close();
		}
	},
	session
});
