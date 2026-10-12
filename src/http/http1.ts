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
	return req.body && req.body.length ? concat(Buffer.from(head), req.body) : new Uint8Array(Buffer.from(head));
}

const indexOfCRLFCRLF = (b: Uint8Array): number => {
	for (let i = 0; i + 3 < b.length; i++) if (b[i] === 13 && b[i + 1] === 10 && b[i + 2] === 13 && b[i + 3] === 10) return i;
	return -1;
};

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

function dechunk(b: Uint8Array): Uint8Array {
	const out: Uint8Array[] = [];
	let i = 0;
	for (;;) {
		let j = i;
		while (j + 1 < b.length && !(b[j] === 13 && b[j + 1] === 10)) j++;
		const size = parseInt(Buffer.from(b.subarray(i, j)).toString('ascii').trim(), 16);
		i = j + 2;
		if (!Number.isFinite(size) || size === 0) break;
		out.push(b.subarray(i, i + size));
		i += size + 2; // skip trailing CRLF of the chunk
	}
	return concat(...out);
}

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
		buf = concat(buf, chunk);
		headEnd = indexOfCRLFCRLF(buf);
	}
	const head = Buffer.from(buf.subarray(0, headEnd)).toString('latin1');
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
	let rest: Uint8Array = buf.subarray(headEnd + 4);

	const te = headers['transfer-encoding'];
	const cl = headers['content-length'];
	const chunked = (Array.isArray(te) ? te.join(',') : te ?? '').toLowerCase().includes('chunked');
	// Accumulate into an array + one concat at the end (avoids O(n²) regrow per read).
	const parts: Uint8Array[] = [rest];
	if (chunked) {
		let tail = rest; // only the last ≤7 bytes are needed to detect the end marker
		while (!isChunkEnd(tail)) {
			const chunk = await read();
			if (chunk === null) break;
			parts.push(chunk);
			tail = concat(tail, chunk);
			if (tail.length > 7) tail = tail.subarray(tail.length - 7);
		}
		rest = dechunk(concat(...parts));
	} else if (cl !== undefined) {
		const want = Number(Array.isArray(cl) ? cl[0] : cl);
		let have = rest.length;
		while (have < want) {
			const chunk = await read();
			if (chunk === null) break;
			parts.push(chunk);
			have += chunk.length;
		}
		rest = concat(...parts).subarray(0, want);
	} else {
		for (;;) {
			const chunk = await read();
			if (chunk === null) break;
			parts.push(chunk);
		}
		rest = concat(...parts);
	}

	const body = decompress(rest, headers['content-encoding']);
	// Reusable only if the body was definitely framed (CL/chunked). The read-to-EOF
	// branch means the server signalled end-of-body by closing → not reusable.
	const reusable = (chunked || cl !== undefined) && !connClose;
	return {
		status,
		statusText,
		headers,
		body,
		reusable,
		text: () => Buffer.from(body).toString('utf8'),
		json: <T>() => JSON.parse(Buffer.from(body).toString('utf8')) as T
	};
}

/** Chunked body is done once we see "0\r\n\r\n". */
function isChunkEnd(b: Uint8Array): boolean {
	if (b.length < 5) return false;
	const s = Buffer.from(b.subarray(Math.max(0, b.length - 7))).toString('ascii');
	return s.endsWith('0\r\n\r\n');
}
