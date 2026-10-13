// readResponse / Dechunker: framing fuzz + the two chunked bugs the old parser had.
// Run: bun test/http1.test.ts
import assert from 'node:assert';
import { readResponse, Dechunker, serializeRequest } from '../src/http/http1';

function mulberry32(seed: number) {
	let a = seed >>> 0;
	return () => {
		a = (a + 0x6d2b79f5) | 0;
		let t = Math.imul(a ^ (a >>> 15), 1 | a);
		t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	};
}
const enc = (s: string) => new Uint8Array(Buffer.from(s, 'latin1'));
// A read() that yields `buf` in the given split points, then null; throws if read after the end.
function reader(buf: Uint8Array, splits: number[]) {
	const points = [0, ...splits.filter((p) => p > 0 && p < buf.length).sort((a, b) => a - b), buf.length];
	let k = 0;
	let ended = false;
	return async () => {
		if (k >= points.length - 1) {
			assert.ok(!ended, 'read() called after it already returned null');
			ended = true;
			return null;
		}
		return buf.subarray(points[k]!, points[++k]!);
	};
}
const splitsFor = (len: number, rnd: () => number, n = 6) => Array.from({ length: n }, () => Math.floor(rnd() * len));

// Build a chunked body with random chunk sizes, extensions, mixed-case hex, optional trailers.
function makeChunked(body: Uint8Array, rnd: () => number, trailers: boolean) {
	const out: number[] = [];
	const pushStr = (s: string) => {
		for (const ch of enc(s)) out.push(ch);
	};
	let i = 0;
	while (i < body.length) {
		const size = 1 + Math.floor(rnd() * Math.min(5000, body.length - i));
		let hex = size.toString(16);
		if (rnd() < 0.3) hex = hex.toUpperCase();
		pushStr(hex + (rnd() < 0.3 ? ';ext=' + Math.floor(rnd() * 99) : '') + '\r\n');
		for (let j = 0; j < size; j++) out.push(body[i + j]!);
		pushStr('\r\n');
		i += size;
	}
	pushStr('0\r\n');
	if (trailers) pushStr('X-Trace: abc\r\nX-Rows: 5\r\n');
	pushStr('\r\n');
	return new Uint8Array(out);
}
const resp = (headers: string, body: Uint8Array) => {
	const h = enc(headers);
	const out = new Uint8Array(h.length + body.length);
	out.set(h);
	out.set(body, h.length);
	return out;
};

let checks = 0;
for (let seed = 1; seed <= 200; seed++) {
	const rnd = mulberry32(seed);
	const bodyLen = Math.floor(rnd() * 200000);
	const body = new Uint8Array(bodyLen);
	for (let i = 0; i < bodyLen; i++) body[i] = (i * 2654435761) & 0xff;
	const trailers = rnd() < 0.5;
	const wire = resp('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: x\r\n\r\n', makeChunked(body, rnd, trailers));
	const r = await readResponse(reader(wire, splitsFor(wire.length, rnd, 8)));
	assert.equal(r.status, 200, `seed ${seed} status`);
	assert.deepEqual(r.body, body, `seed ${seed} chunked body (${bodyLen}B, trailers=${trailers})`);
	assert.equal(r.reusable, true, `seed ${seed} reusable`);
	checks++;
}

// Regression 1: a read boundary right after a data chunk ending in "0\r\n" (old false positive).
{
	const body = enc('abc0\r\nxyz'); // contains "0\r\n" mid-body
	const wire = resp('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n', makeChunked(body, mulberry32(7), false));
	// split after every byte to hit the worst case
	const r = await readResponse(reader(wire, Array.from({ length: wire.length }, (_, i) => i)));
	assert.deepEqual(r.body, body, 'regression: mid-body 0\\r\\n not treated as end');
}
// Regression 2: trailers after the 0 chunk (old parser hung / read past end).
{
	const wire = resp('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n', enc('5\r\nhello\r\n0\r\nX-A: 1\r\nX-B: 2\r\n\r\n'));
	const r = await readResponse(reader(wire, [20, 30]));
	assert.deepEqual(r.body, enc('hello'), 'regression: trailers consumed, body correct');
	assert.equal(r.reusable, true);
}
// Surplus after the terminator (pipelined next response) is dropped, read() not called again.
{
	const wire = resp('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n', enc('3\r\nabc\r\n0\r\n\r\nHTTP/1.1 200 OK\r\n'));
	const r = await readResponse(reader(wire, []));
	assert.deepEqual(r.body, enc('abc'), 'surplus after terminator dropped');
}

// Malformed chunked must throw.
for (const [bad, why] of [
	['zz\r\nabc\r\n0\r\n\r\n', 'non-hex size'],
	['3\r\nabcX0\r\n\r\n', 'missing CRLF after data'],
	['3\nabc\r\n0\r\n\r\n', 'bare LF after size'],
	['fffffffffffffff\r\n', 'size too long']
] as const) {
	let threw = false;
	try {
		await readResponse(reader(resp('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n', enc(bad)), []));
	} catch {
		threw = true;
	}
	assert.ok(threw, `malformed chunked throws: ${why}`);
}

// Content-Length: exact, split across reads, surplus dropped, zero-length.
{
	const body = new Uint8Array(5000).map((_, i) => i & 0xff);
	const wire = resp(`HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\n\r\n`, body);
	const r = await readResponse(reader(wire, splitsFor(wire.length, mulberry32(3), 10)));
	assert.deepEqual(r.body, body, 'CL body split across reads');
	assert.equal(r.reusable, true);

	const sur = resp(`HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n`, enc('abcEXTRA'));
	const r2 = await readResponse(reader(sur, []));
	assert.deepEqual(r2.body, enc('abc'), 'CL surplus dropped');

	const r3 = await readResponse(reader(resp('HTTP/1.1 204 No Content\r\n\r\n', new Uint8Array(0)), []), 'GET');
	assert.equal(r3.body.length, 0, '204 no body');
}
// Content-Length truncated by EOF → partial body, not reusable.
{
	const wire = resp('HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n', enc('short'));
	const r = await readResponse(reader(wire, []));
	assert.equal(r.body.length, 5, 'truncated CL returns partial');
	assert.equal(r.reusable, false, 'truncated CL not reusable');
}
// EOF-delimited body (no framing) → body read to close, not reusable.
{
	const wire = resp('HTTP/1.1 200 OK\r\nContent-Type: x\r\n\r\n', enc('bodybytes'));
	const r = await readResponse(reader(wire, [15]));
	assert.deepEqual(r.body, enc('bodybytes'), 'EOF-delimited body');
	assert.equal(r.reusable, false, 'EOF body not reusable');
}
// HEAD: no body even with Content-Length present.
{
	const r = await readResponse(reader(resp('HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n', new Uint8Array(0)), []), 'HEAD');
	assert.equal(r.body.length, 0, 'HEAD no body');
	assert.equal(r.reusable, true);
}
// serializeRequest shape.
{
	const b = serializeRequest({ method: 'GET', host: 'h', path: '/p', headers: { Host: 'h', 'X-A': '1' } });
	assert.equal(Buffer.from(b).toString('latin1'), 'GET /p HTTP/1.1\r\nHost: h\r\nX-A: 1\r\n\r\n', 'request bytes');
}

console.log(`http1: OK (${checks} chunked fuzz responses)`);
