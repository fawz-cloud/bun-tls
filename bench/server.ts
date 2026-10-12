// Local TLS 1.3 server for the benchmarks: 1 KB body at `/`, POST echoes the received
// byte count. Needs a self-signed cert in bench/ (see README → Benchmarks).
import { readFileSync } from 'node:fs';

const dir = import.meta.dir;
const small = 'x'.repeat(1024);
const server = Bun.serve({
	port: 48443,
	tls: { key: readFileSync(`${dir}/key.pem`), cert: readFileSync(`${dir}/cert.pem`) },
	async fetch(req) {
		if (req.method === 'POST') return new Response(String((await req.arrayBuffer()).byteLength));
		return new Response(small, { headers: { 'content-type': 'text/plain' } });
	}
});
console.log(`bench server on https://localhost:${server.port}/`);
