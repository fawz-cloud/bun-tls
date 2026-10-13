// HTTP/3 (RFC 9114) + QPACK (RFC 9204) over a QuicConnection. QPACK uses the static table
// only (we advertise dynamic-table capacity 0), so field lines are indexed-static, literal
// with a static name reference, or literal with a literal name — no dynamic table needed.
import { writeVarint, readVarint } from '../quic/varint';
import { streamFrame, maxDataFrame, maxStreamDataFrame, Reassembler } from '../quic/frames';
import { concat } from '../core/bytes';
import { huffmanDecode } from './h2';
import { STREAM_WINDOW, CONN_WINDOW, type QuicConnection } from '../quic/connection';

// RFC 9204 Appendix A — QPACK static table (index → [name, value]).
const STATIC: [string, string][] = [
	[':authority', ''], [':path', '/'], ['age', '0'], ['content-disposition', ''], ['content-length', '0'], ['cookie', ''], ['date', ''], ['etag', ''],
	['if-modified-since', ''], ['if-none-match', ''], ['last-modified', ''], ['link', ''], ['location', ''], ['referer', ''], ['set-cookie', ''],
	[':method', 'CONNECT'], [':method', 'DELETE'], [':method', 'GET'], [':method', 'HEAD'], [':method', 'OPTIONS'], [':method', 'POST'], [':method', 'PUT'],
	[':scheme', 'http'], [':scheme', 'https'], [':status', '103'], [':status', '200'], [':status', '304'], [':status', '404'], [':status', '503'],
	['accept', '*/*'], ['accept', 'application/dns-message'], ['accept-encoding', 'gzip, deflate, br'], ['accept-ranges', 'bytes'],
	['access-control-allow-headers', 'cache-control'], ['access-control-allow-headers', 'content-type'], ['access-control-allow-origin', '*'],
	['cache-control', 'max-age=0'], ['cache-control', 'max-age=2592000'], ['cache-control', 'max-age=604800'], ['cache-control', 'no-cache'],
	['cache-control', 'no-store'], ['cache-control', 'public, max-age=31536000'], ['content-encoding', 'br'], ['content-encoding', 'gzip'],
	['content-type', 'application/dns-message'], ['content-type', 'application/javascript'], ['content-type', 'application/json'],
	['content-type', 'application/x-www-form-urlencoded'], ['content-type', 'image/gif'], ['content-type', 'image/jpeg'], ['content-type', 'image/png'],
	['content-type', 'text/css'], ['content-type', 'text/html; charset=utf-8'], ['content-type', 'text/plain'], ['content-type', 'text/plain;charset=utf-8'],
	['range', 'bytes=0-'], ['strict-transport-security', 'max-age=31536000'], ['strict-transport-security', 'max-age=31536000; includesubdomains'],
	['strict-transport-security', 'max-age=31536000; includesubdomains; preload'], ['vary', 'accept-encoding'], ['vary', 'origin'],
	['x-content-type-options', 'nosniff'], ['x-xss-protection', '1; mode=block'], [':status', '100'], [':status', '204'], [':status', '206'],
	[':status', '302'], [':status', '400'], [':status', '403'], [':status', '421'], [':status', '425'], [':status', '500'],
	['accept-language', ''], ['access-control-allow-credentials', 'FALSE'], ['access-control-allow-credentials', 'TRUE'], ['access-control-allow-headers', '*'],
	['access-control-allow-methods', 'get'], ['access-control-allow-methods', 'get, post, options'], ['access-control-allow-methods', 'options'],
	['access-control-expose-headers', 'content-length'], ['access-control-request-headers', 'content-type'], ['access-control-request-method', 'get'],
	['access-control-request-method', 'post'], ['alt-svc', 'clear'], ['authorization', ''], ['content-security-policy', "script-src 'none'; object-src 'none'; base-uri 'none'"],
	['early-data', '1'], ['expect-ct', ''], ['forwarded', ''], ['if-range', ''], ['origin', ''], ['purpose', 'prefetch'], ['server', ''], ['timing-allow-origin', '*'],
	['upgrade-insecure-requests', '1'], ['user-agent', ''], ['x-forwarded-for', ''], ['x-frame-options', 'deny'], ['x-frame-options', 'sameorigin']
];
// name → first static index (for literal-with-name-reference encoding).
const NAME_IDX = new Map<string, number>();
for (let i = STATIC.length - 1; i >= 0; i--) NAME_IDX.set(STATIC[i]![0], i);
// (name,value) → index for fully-indexed encoding.
const PAIR_IDX = new Map<string, number>();
STATIC.forEach(([n, v], i) => PAIR_IDX.set(n + '\0' + v, i));

// ── QPACK integer coding (RFC 9204 §4.1.1 / HPACK §5.1) ──
function encInt(base: number, prefix: number, value: number): number[] {
	const max = (1 << prefix) - 1;
	if (value < max) return [base | value];
	const out = [base | max];
	value -= max;
	while (value >= 128) {
		out.push((value & 0x7f) | 0x80);
		value >>= 7;
	}
	out.push(value);
	return out;
}
function decInt(b: Uint8Array, i: number, prefix: number): { value: number; i: number } {
	const max = (1 << prefix) - 1;
	let value = b[i]! & max;
	i++;
	if (value < max) return { value, i };
	let m = 0;
	for (;;) {
		const byte = b[i++]!;
		value += (byte & 0x7f) * Math.pow(2, m);
		m += 7;
		if (!(byte & 0x80)) break;
	}
	return { value, i };
}

function encStr(s: string): number[] {
	const bytes = Buffer.from(s); // no Huffman on the way out (simpler; servers accept it)
	return [...encInt(0, 7, bytes.length), ...bytes];
}

/** Encode a field section (RFC 9204 §4.5): 2-byte all-zero prefix + representations. */
export function qpackEncode(fields: [string, string][]): Uint8Array {
	const out: number[] = [0x00, 0x00]; // Required Insert Count = 0, Base = 0
	for (const [name, value] of fields) {
		const pair = PAIR_IDX.get(name + '\0' + value);
		if (pair !== undefined) {
			out.push(...encInt(0xc0, 6, pair)); // indexed, static
			continue;
		}
		const ni = NAME_IDX.get(name);
		if (ni !== undefined) {
			out.push(...encInt(0x50, 4, ni)); // literal, name ref, static (0x40|T 0x10)
			out.push(...encStr(value));
		} else {
			const nb = Buffer.from(name);
			out.push(...encInt(0x20, 3, nb.length)); // literal name (001, H=0)
			out.push(...nb);
			out.push(...encStr(value));
		}
	}
	return new Uint8Array(out);
}

/** Decode a field section → [name, value][]. Static table + literals only. */
export function qpackDecode(b: Uint8Array): [string, string][] {
	let i = 0;
	i = decInt(b, i, 8).i; // Required Insert Count (prefix 8)
	i = decInt(b, i, 7).i; // Base (sign bit + prefix 7)
	const out: [string, string][] = [];
	const readStr = (): string => {
		const huff = (b[i]! & 0x80) !== 0;
		const r = decInt(b, i, 7);
		i = r.i;
		const raw = b.subarray(i, i + r.value);
		i += r.value;
		return huff ? huffmanDecode(raw) : Buffer.from(raw).toString('latin1');
	};
	while (i < b.length) {
		const first = b[i]!;
		if (first & 0x80) {
			// indexed
			const r = decInt(b, i, 6);
			i = r.i;
			const e = STATIC[r.value];
			if (e) out.push([e[0], e[1]]);
		} else if (first & 0x40) {
			// literal with name reference
			const r = decInt(b, i, 4);
			i = r.i;
			const name = STATIC[r.value]?.[0] ?? '';
			out.push([name, readStr()]);
		} else if (first & 0x20) {
			// literal with literal name
			const huffName = (first & 0x08) !== 0;
			const r = decInt(b, i, 3);
			i = r.i;
			const nb = b.subarray(i, i + r.value);
			i += r.value;
			const name = huffName ? huffmanDecode(nb) : Buffer.from(nb).toString('latin1');
			out.push([name, readStr()]);
		} else {
			break; // post-base / dynamic — not used (capacity 0)
		}
	}
	return out;
}

// ── HTTP/3 frames (RFC 9114 §7.1): varint type + varint length + payload ──
const h3Frame = (type: number, payload: Uint8Array): Uint8Array => concat(writeVarint(type), writeVarint(payload.length), payload);
function encodeSettings(): Uint8Array {
	return new Uint8Array([...writeVarint(0x01), ...writeVarint(0), ...writeVarint(0x06), ...writeVarint(0x4000), ...writeVarint(0x07), ...writeVarint(0)]);
}

export interface H3Response {
	status: number;
	headers: Record<string, string | string[]>;
	body: Uint8Array;
}

/** Perform one HTTP/3 GET-style request over a completed QuicConnection. */
export async function h3Request(conn: QuicConnection, method: string, authority: string, path: string, extra: [string, string][] = [], body?: Uint8Array, timeoutMs = 10000): Promise<H3Response> {
	// Client unidirectional streams: control (2) = SETTINGS, QPACK encoder (6) + decoder (10) = empty.
	conn.send1rtt(concat(
		streamFrame(2, 0, concat(writeVarint(0x00), h3Frame(0x04, encodeSettings())), false),
		streamFrame(6, 0, writeVarint(0x02), false),
		streamFrame(10, 0, writeVarint(0x03), false)
	));
	// Request on client bidi stream 0: HEADERS (+ DATA for a body), FIN at the end.
	const fields = qpackEncode([[':method', method], [':scheme', 'https'], [':authority', authority], [':path', path], ...extra]);
	let reqData = h3Frame(0x01, fields);
	if (body && body.length) reqData = concat(reqData, h3Frame(0x00, body));
	conn.send1rtt(streamFrame(0, 0, reqData, true));

	// Reassemble stream 0 (our response), parse HTTP/3 frames.
	const stream = new Reassembler();
	let finOffset = -1;
	let buf: Uint8Array = new Uint8Array(0);
	let status = 0;
	const headers: Record<string, string | string[]> = {};
	const bodyParts: Uint8Array[] = [];
	const deadline = Date.now() + timeoutMs;
	// Flow control: keep the peer's credit a full window ahead of what we consumed, or a body
	// past STREAM_WINDOW (256 KiB) stalls the server forever.
	let maxStream = STREAM_WINDOW;
	let maxData = CONN_WINDOW;
	let complete = false;

	while (!complete && Date.now() < deadline) {
		const frames = await conn.recv1rtt(deadline - Date.now());
		if (!frames.length && conn.closed) break;
		for (const f of frames) {
			if (f.type !== 'stream' || f.id !== 0) continue;
			stream.push(f.offset, f.data);
			if (f.fin) finOffset = f.offset + f.data.length;
		}
		const fresh = stream.take();
		if (fresh.length) buf = buf.length ? concat(buf, fresh) : fresh;
		const credit: Uint8Array[] = [];
		if (maxStream - stream.consumed < STREAM_WINDOW / 2) credit.push(maxStreamDataFrame(0, (maxStream = stream.consumed + STREAM_WINDOW)));
		if (maxData - stream.consumed < CONN_WINDOW / 2) credit.push(maxDataFrame((maxData = stream.consumed + CONN_WINDOW)));
		if (credit.length) conn.send1rtt(concat(...credit));
		// parse complete HTTP/3 frames out of buf
		let o = 0;
		for (;;) {
			const t = readVarint(buf, o);
			if (o + t.len >= buf.length) break;
			const l = readVarint(buf, o + t.len);
			const hdr = t.len + l.len;
			if (o + hdr + l.value > buf.length) break; // frame not fully arrived
			const payload = buf.subarray(o + hdr, o + hdr + l.value);
			if (t.value === 0x01) {
				for (const [n, v] of qpackDecode(payload)) {
					if (n === ':status') status = Number(v);
					else if (n.startsWith(':')) continue;
					else {
						const prev = headers[n];
						if (prev === undefined) headers[n] = v;
						else if (Array.isArray(prev)) prev.push(v);
						else headers[n] = [prev, v];
					}
				}
			} else if (t.value === 0x00) {
				bodyParts.push(new Uint8Array(payload));
			}
			o += hdr + l.value;
		}
		buf = buf.subarray(o);
		complete = finOffset >= 0 && stream.consumed >= finOffset && buf.length === 0;
	}
	// Never hand back a partial response as if it were whole.
	if (!complete) throw new Error(`h3: response incomplete — the stream did not finish (${stream.consumed} bytes${finOffset >= 0 ? ` of ${finOffset}` : ', no FIN'}) before the deadline`);
	if (!status) throw new Error('h3: response stream ended without a HEADERS frame');
	return { status, headers, body: concat(...bodyParts) };
}
