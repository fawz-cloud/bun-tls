// HTTP/1.1 over the TLS channel (dart:io is h1). Serialize a request + parse a
// response (Content-Length / chunked / read-to-EOF) + decompress gzip/deflate/br.
// Transport-agnostic: given writeApp + readApp from the TlsClient.
import zlib from 'node:zlib';
import { concat } from '../core/bytes';

export interface HttpResponse {
	status: number;
	statusText: string;
	headers: Record<string, string | string[]>;
	body: Uint8Array;
	/** Connection can be reused (framed body — CL/chunked/no-body — and no `Connection: close`). */
	reusable: boolean;
	text(): string;
	json<T = unknown>(): T;
}

interface HttpRequest {
	method: string;
	host: string;
	path: string;
	headers: Record<string, string>;
	body?: Uint8Array;
}

export function serializeRequest(req: HttpRequest): Uint8Array {
	const lines = [`${req.method} ${req.path} HTTP/1.1`];
	for (const [k, v] of Object.entries(req.headers)) lines.push(`${k}: ${v}`);
	const head = lines.join('\r\n') + '\r\n\r\n';
	// Buffer IS a Uint8Array; the body is written separately by roundtrip, so no copy here.
	return req.body && req.body.length ? concat(Buffer.from(head), req.body) : Buffer.from(head);
}

// Resume the CRLFCRLF scan from `from` (minus 3, to catch a terminator split across feeds).
const indexOfCRLFCRLF = (b: Uint8Array, from = 0): number => {
	for (let i = Math.max(0, from - 3); i + 3 < b.length; i++) if (b[i] === 13 && b[i + 1] === 10 && b[i + 2] === 13 && b[i + 3] === 10) return i;
	return -1;
};

// Join zero-copy views into one exact-size buffer (no `concat(...parts)` spread, which can hit
// the argument limit for many tiny chunks). Keeps body.byteOffset===0 so P8 can transfer it.
function join(parts: Uint8Array[], total: number): Uint8Array {
	if (parts.length === 1 && parts[0]!.length === total) return parts[0]!;
	const out = new Uint8Array(total);
	let o = 0;
	for (const p of parts) {
		out.set(p, o);
		o += p.length;
	}
	return out;
}

function parseHead(head: string): { status: number; statusText: string; headers: Record<string, string | string[]> } {
	const [statusLine, ...rest] = head.split('\r\n');
	const m = /^HTTP\/1\.[01] (\d{3}) ?(.*)$/.exec(statusLine!);
	if (!m) throw new Error('malformed status line: ' + statusLine);
	const headers: Record<string, string | string[]> = {};
	for (const line of rest) {
		const i = line.indexOf(':');
		if (i < 0) continue;
		const k = line.slice(0, i).trim().toLowerCase();
		const v = line.slice(i + 1).trim();
		const prev = headers[k];
		if (prev === undefined) headers[k] = v;
		else if (Array.isArray(prev)) prev.push(v);
		else headers[k] = [prev, v];
	}
	return { status: Number(m[1]), statusText: m[2] ?? '', headers };
}

// Incremental chunked-body decoder (RFC 9112 §7.1). A byte-level state machine so any split is
// handled, chunk extensions (`;name=val`) and trailers are skipped, and a missing CR/LF where
// the grammar requires one throws instead of silently truncating. push() returns true at the
// terminating 0-size chunk; data chunks are collected as zero-copy views in `parts`.
const enum CS {
	Size, // reading hex size digits (and any ;extension), until CR
	SizeLF, // seen CR after the size line, expect LF
	Data, // copying `remaining` body bytes
	DataCR, // expect CR after a chunk's data
	DataLF, // expect LF after that CR
	Trailer, // reading trailer lines after the 0 chunk
	TrailerCR, // seen CR, expect LF (empty line ends the body)
	Done
}
export class Dechunker {
	parts: Uint8Array[] = [];
	total = 0;
	private st = CS.Size;
	private size = 0; // current chunk size being parsed
	private remaining = 0; // body bytes still to copy in Data
	private sawDigit = false;
	private inExt = false; // past the ';' of a chunk extension
	private trailerLen = 0; // chars on the current trailer line

	/** Feed bytes; returns true once the body is complete. Throws on malformed framing. */
	push(b: Uint8Array): boolean {
		let i = 0;
		while (i < b.length) {
			const c = b[i]!;
			switch (this.st) {
				case CS.Size:
					if (c === 13) {
						if (!this.sawDigit) throw new Error('chunked: missing size');
						this.st = CS.SizeLF;
						i++;
					} else if (c === 59) {
						this.inExt = true; // ';' → extension, skip to CR
						i++;
					} else if (this.inExt) {
						i++; // ignore extension bytes
					} else {
						const d = hexVal(c);
						if (d < 0) throw new Error('chunked: bad size byte');
						if (++this.sizeDigits > 13) throw new Error('chunked: size too long'); // 13 hex = 52 bits, past 2^53
						this.size = this.size * 16 + d;
						this.sawDigit = true;
						i++;
					}
					break;
				case CS.SizeLF:
					if (c !== 10) throw new Error('chunked: expected LF after size');
					i++;
					if (this.size === 0) {
						this.st = CS.Trailer; // last chunk → trailers then end
						this.trailerLen = 0;
					} else {
						this.remaining = this.size;
						this.st = CS.Data;
					}
					this.size = 0;
					this.sawDigit = false;
					this.inExt = false;
					this.sizeDigits = 0;
					break;
				case CS.Data: {
					const take = Math.min(this.remaining, b.length - i);
					this.parts.push(b.subarray(i, i + take));
					this.total += take;
					this.remaining -= take;
					i += take;
					if (this.remaining === 0) this.st = CS.DataCR;
					break;
				}
				case CS.DataCR:
					if (c !== 13) throw new Error('chunked: expected CR after data');
					this.st = CS.DataLF;
					i++;
					break;
				case CS.DataLF:
					if (c !== 10) throw new Error('chunked: expected LF after data');
					this.st = CS.Size;
					i++;
					break;
				case CS.Trailer:
					if (c === 13) {
						this.st = this.trailerLen === 0 ? CS.Done : CS.TrailerCR;
						i++;
						if (this.st === CS.Done) return true; // empty line → body complete
					} else {
						this.trailerLen++;
						i++;
					}
					break;
				case CS.TrailerCR:
					if (c !== 10) throw new Error('chunked: expected LF in trailer');
					this.st = CS.Trailer;
					this.trailerLen = 0;
					i++;
					break;
				case CS.Done:
					return true;
			}
		}
		return this.st === CS.Done;
	}
	private sizeDigits = 0;
}
const hexVal = (c: number): number => (c >= 48 && c <= 57 ? c - 48 : c >= 97 && c <= 102 ? c - 87 : c >= 65 && c <= 70 ? c - 55 : -1);

function decompress(body: Uint8Array, enc?: string | string[]): Uint8Array {
	const e = (Array.isArray(enc) ? enc.join(',') : enc ?? '').toLowerCase();
	try {
		if (e.includes('zstd') && typeof zlib.zstdDecompressSync === 'function') return new Uint8Array(zlib.zstdDecompressSync(body));
		if (e.includes('br')) return new Uint8Array(zlib.brotliDecompressSync(body));
		if (e.includes('gzip')) return new Uint8Array(zlib.gunzipSync(body));
		if (e.includes('deflate')) return new Uint8Array(zlib.inflateSync(body));
	} catch {
		return body; // not actually compressed / corrupt → return as-is
	}
	return body;
}

/** Read one full response from a read() function (TlsClient.readApp). */
export async function readResponse(read: () => Promise<Uint8Array | null>, method = 'GET'): Promise<HttpResponse> {
	let buf: Uint8Array = new Uint8Array(0);
	let headEnd = -1;
	while (headEnd < 0) {
		const chunk = await read();
		if (chunk === null) throw new Error('connection closed before full header');
		const prev = buf.length;
		buf = buf.length ? concat(buf, chunk) : chunk; // adopt the first chunk, concat only if a second is needed
		headEnd = indexOfCRLFCRLF(buf, prev);
	}
	const head = Buffer.from(buf.buffer, buf.byteOffset, headEnd).toString('latin1'); // view, no copy
	const { status, statusText, headers } = parseHead(head);
	const connClose = (Array.isArray(headers['connection']) ? headers['connection'].join(',') : headers['connection'] ?? '')
		.toLowerCase()
		.includes('close');
	// Responses that carry no body: don't fall into the read-to-EOF branch below
	// (it would block forever on a keep-alive connection the server keeps open).
	if (method === 'HEAD' || status === 204 || status === 304 || (status >= 100 && status < 200)) {
		const body = new Uint8Array(0);
		return { status, statusText, headers, body, reusable: !connClose, text: () => '', json: <T>() => null as T };
	}
	const rest: Uint8Array = buf.subarray(headEnd + 4);

	const te = headers['transfer-encoding'];
	const cl = headers['content-length'];
	const chunked = (Array.isArray(te) ? te.join(',') : te ?? '').toLowerCase().includes('chunked');
	let framed: Uint8Array;
	let complete = true;
	if (chunked) {
		const dc = new Dechunker();
		let done = dc.push(rest);
		while (!done) {
			const chunk = await read();
			if (chunk === null) {
				complete = false;
				break;
			}
			done = dc.push(chunk);
		}
		framed = join(dc.parts.length ? dc.parts : [new Uint8Array(0)], dc.total);
	} else if (cl !== undefined) {
		const want = Number(Array.isArray(cl) ? cl[0] : cl);
		if (!Number.isFinite(want) || want <= 0) {
			framed = new Uint8Array(0);
		} else {
			const parts: Uint8Array[] = [rest.length > want ? rest.subarray(0, want) : rest];
			let have = parts[0]!.length;
			while (have < want) {
				const chunk = await read();
				if (chunk === null) {
					complete = false;
					break;
				}
				const piece = have + chunk.length > want ? chunk.subarray(0, want - have) : chunk;
				parts.push(piece);
				have += piece.length;
			}
			framed = join(parts, have);
		}
	} else {
		// No framing → read to EOF; the server closed to signal the end, so not reusable.
		const parts: Uint8Array[] = rest.length ? [rest] : [];
		let total = rest.length;
		for (;;) {
			const chunk = await read();
			if (chunk === null) break;
			parts.push(chunk);
			total += chunk.length;
		}
		framed = join(parts.length ? parts : [new Uint8Array(0)], total);
		complete = false; // EOF-delimited → treat as non-reusable below
	}

	const body = decompress(framed, headers['content-encoding']);
	// Reusable only if the body was framed (CL/chunked), fully received, and no Connection: close.
	const reusable = (chunked || cl !== undefined) && complete && !connClose;
	return {
		status,
		statusText,
		headers,
		body,
		reusable,
		text: () => Buffer.from(body.buffer, body.byteOffset, body.length).toString('utf8'),
		json: <T>() => JSON.parse(Buffer.from(body.buffer, body.byteOffset, body.length).toString('utf8')) as T
	};
}
