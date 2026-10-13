// bun-tls test runner. `bun test/all.ts` = offline (crypto, chacha).
// `bun test/all.ts --live` = also network (handshake, JA3/JA4 echo, POST, session).
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';

const here = import.meta.dir;
const live = process.argv.includes('--live');
const files = ['crypto.test.ts', 'chacha.test.ts', 'record.test.ts', 'resumption.test.ts', 'cookie.test.ts', 'x509.test.ts', 'quic.test.ts', ...(live ? ['live.test.ts'] : [])];
let fail = 0;
for (const f of files) {
	const r = spawnSync('bun', [join(here, f)], { stdio: 'inherit' });
	if (r.status !== 0) fail++;
}
console.log(fail ? `\n${fail}/${files.length} FAILED` : `\n${files.length}/${files.length} passed${live ? '' : ' (use --live for network tests)'}`);
process.exit(fail ? 1 : 0);
