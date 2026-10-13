#!/usr/bin/env bun
// bun-tls CLI. Currently one command:
//   bun src/cli.ts proxy [--port 8888] [--host 127.0.0.1] [--persona chrome] [--no-verify]
import { startProxy } from './proxy';

const argv = process.argv.slice(2);
const cmd = argv[0];
const flag = (name: string): string | undefined => {
	const i = argv.indexOf('--' + name);
	return i >= 0 ? argv[i + 1] : undefined;
};

if (cmd === 'proxy') {
	const server = startProxy({
		port: flag('port') ? Number(flag('port')) : undefined,
		host: flag('host'),
		persona: flag('persona'),
		verify: argv.includes('--no-verify') ? false : undefined
	});
	console.log(`bun-tls proxy on http://${server.hostname}:${server.port} — persona=${flag('persona') ?? 'chrome'}`);
	console.log(`  HTTP_PROXY=http://${server.hostname}:${server.port} curl http://example.com/`);
	console.log(`  curl 'http://${server.hostname}:${server.port}/https://example.com/'`);
} else {
	console.log('usage: bun src/cli.ts proxy [--port 8888] [--host 127.0.0.1] [--persona chrome] [--no-verify]');
	process.exit(cmd ? 1 : 0);
}
