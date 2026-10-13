// fetch()-compatible entry point: same shape as the global fetch (URL/Request-ish input
// + init), returning a standard Web `Response` with a STREAMING body — plus bun-tls's
// fingerprint control (`persona` / `fingerprint`) in the init. Drop-in for code that
// already calls fetch; the body streams instead of buffering (large downloads, SSE).
import zlib from 'node:zlib';
import { Readable } from 'node:stream';
import { openConnection, type OpenOptions } from './client';
import { serializeRequest } from './http1';
import { h2Request } from './h2';
import { withH2 } from './client';
import { modern } from '../fp/fingerprints';
import { resolvePersona, personaHeaders } from '../fp/personas';
import type { Persona } from '../fp/personas';
import type { Fingerprint } from '../tls/clienthello';
import type { OcspMode } from '../tls/verify';
import type { TlsConn } from '../tls/handshake';
import { concat } from '../core/bytes';
import zlib2 from 'node:zlib';
import { QuicConnection } from '../quic/connection';
import { h3Request } from './h3';

export interface FetchInit {
	method?: string;
	headers?: Record<string, string> | Headers | [string, string][];
	body?: string | Uint8Array | ArrayBuffer;
	/** Fingerprint control (bun-tls extension). */
	persona?: string | Persona;
	fingerprint?: Fingerprint;
	proxy?: string;
	verify?: boolean;
	ocsp?: OcspMode;
	tls12?: boolean;
	http2?: boolean;
	/** Use HTTP/3 (QUIC). Opens a fresh QUIC connection; body is buffered. */
	http3?: boolean;
	timeoutMs?: number;
	/** Abort the request (standard AbortSignal). */
	signal?: AbortSignal;
}

function toHeaderObject(h: FetchInit['headers']): Record<string, string> {
	const out: Record<string, string> = {};
	if (!h) return out;
	if (h instanceof Headers) h.forEach((v, k) => (out[k] = v));
	else if (Array.isArray(h)) for (const [k, v] of h) out[k] = v;
	else Object.assign(out, h);
	return out;
}

/** A Node decompressor transform for a content-encoding, or null for identity. */
function decompressor(enc: string): zlib.BrotliDecompress | zlib.Gunzip | zlib.Inflate | null {
	if (enc.includes('zstd') && typeof (zlib as { createZstdDecompress?: unknown }).createZstdDecompress === 'function')
		return (zlib as unknown as { createZstdDecompress(): zlib.BrotliDecompress }).createZstdDecompress();
	if (enc.includes('br')) return zlib.createBrotliDecompress();
	if (enc.includes('gzip')) return zlib.createGunzip();
	if (enc.includes('deflate')) return zlib.createInflate();
	return null;
}

/** Pull framed (de-chunked) body bytes off the TLS connection as they arrive, then close
 *  the connection at end-of-body. A ReadableStream so the caller can consume incrementally. */
function bodyStream(tls: TlsConn, leftover: Uint8Array, chunked: boolean, contentLength: number | null, enc: string, onDone: () => void): ReadableStream<Uint8Array> {
	// Stage 1: raw framed bytes.
	let buf = leftover;
	let received = 0;
	let chunkState: { need: number; inSize: boolean } = { need: -1, inSize: true };
	let ended = false;

	// A chunked decoder fed incrementally; returns decoded bytes + whether the 0-chunk was seen.
	function pumpChunked(): { out: Uint8Array[]; done: boolean } {
		const out: Uint8Array[] = [];
		for (;;) {
			if (chunkState.inSize) {
				const nl = indexOf(buf, 13, 10);
				if (nl < 0) return { out, done: false };
				const size = parseInt(Buffer.from(buf.subarray(0, nl)).toString('ascii').trim(), 16);
				buf = buf.subarray(nl + 2);
				if (!Number.isFinite(size)) return { out, done: true };
				if (size === 0) return { out, done: true };
				chunkState = { need: size, inSize: false };
			}
			if (buf.length < chunkState.need + 2) {
				if (chunkState.need > 0 && buf.length > 0) {
					const take = Math.min(buf.length, chunkState.need);
					out.push(buf.subarray(0, take));
					chunkState.need -= take;
					buf = buf.subarray(take);
				}
				return { out, done: false };
			}
			out.push(buf.subarray(0, chunkState.need));
			buf = buf.subarray(chunkState.need + 2); // skip chunk + trailing CRLF
			chunkState = { need: -1, inSize: true };
		}
	}

	const decomp = decompressor(enc);
	const source = new ReadableStream<Uint8Array>({
		async pull(controller) {
			for (;;) {
				if (chunked) {
					const { out, done } = pumpChunked();
					for (const o of out) if (o.length) controller.enqueue(o);
					if (done) {
						ended = true;
						onDone();
						controller.close();
						return;
					}
					if (out.length) return; // yielded something this pull
				} else if (contentLength !== null) {
					if (buf.length) {
						const take = Math.min(buf.length, contentLength - received);
						if (take > 0) {
							controller.enqueue(buf.subarray(0, take));
							received += take;
							buf = buf.subarray(take);
						}
					}
					if (received >= contentLength) {
						ended = true;
						onDone();
						controller.close();
						return;
					}
					if (buf.length === 0) {
						/* fall through to read more */
					} else return;
				} else {
					if (buf.length) {
						controller.enqueue(buf);
						buf = new Uint8Array(0);
						return;
					}
				}
				const chunk = await tls.readApp();
				if (chunk === null) {
					if (!ended) onDone();
					controller.close();
					return;
				}
				buf = buf.length ? concat(buf, chunk) : chunk;
			}
		},
		cancel() {
			onDone();
		}
	});

	if (!decomp) return source;
	// Stage 2: pipe framed bytes through the decompressor (Node transform ↔ web stream).
	const nodeReadable = Readable.fromWeb(source as import('node:stream/web').ReadableStream<Uint8Array>);
	return Readable.toWeb(nodeReadable.pipe(decomp)) as ReadableStream<Uint8Array>;
}

function indexOf(b: Uint8Array, a: number, c: number): number {
	for (let i = 0; i + 1 < b.length; i++) if (b[i] === a && b[i + 1] === c) return i;
	return -1;
}

const indexOfHeadEnd = (b: Uint8Array): number => {
	for (let i = 0; i + 3 < b.length; i++) if (b[i] === 13 && b[i + 1] === 10 && b[i + 2] === 13 && b[i + 3] === 10) return i;
	return -1;
};

/** fetch(input, init) → Response, with a streaming body and fingerprint control. */
export async function fetch(input: string | URL, init: FetchInit = {}): Promise<Response> {
	const u = typeof input === 'string' ? new URL(input) : input;
	if (u.protocol !== 'https:') throw new Error('bun-tls fetch: only https is supported');
	const host = u.hostname;
	const port = u.port ? Number(u.port) : 443;
	const method = (init.method ?? 'GET').toUpperCase();
	const bodyBytes =
		init.body == null ? undefined : typeof init.body === 'string' ? new Uint8Array(Buffer.from(init.body)) : init.body instanceof ArrayBuffer ? new Uint8Array(init.body) : init.body;

	const P = init.persona ? resolvePersona(init.persona) : null;
	const useH2 = init.http2 ?? P?.http2 ?? false;
	const baseFp = init.fingerprint ?? P?.fingerprint();
	const open: OpenOptions = { host, port, proxy: init.proxy, fingerprint: useH2 ? withH2(baseFp ?? modern()) : baseFp, verify: init.verify, ocsp: init.ocsp, tls12: init.tls12, timeoutMs: init.timeoutMs };

	if (init.http3) {
		const conn = new QuicConnection(host, port);
		await conn.connect(init.timeoutMs ?? 10000);
		try {
			const hs = { ...(P ? personaHeaders(P) : { 'user-agent': 'bun-tls/0.1' }), ...toHeaderObject(init.headers) };
			const extra: [string, string][] = [];
			for (const [k, v] of Object.entries(hs)) if (k.toLowerCase() !== 'host') extra.push([k.toLowerCase(), v]);
			const r = await h3Request(conn, method, u.port ? `${host}:${u.port}` : host, u.pathname + u.search, extra, bodyBytes, init.timeoutMs ?? 10000);
			let body = r.body;
			const enc = (Array.isArray(r.headers['content-encoding']) ? (r.headers['content-encoding'] as string[]).join(',') : (r.headers['content-encoding'] as string) ?? '').toLowerCase();
			try {
				if (enc.includes('zstd') && typeof (zlib2 as { zstdDecompressSync?: unknown }).zstdDecompressSync === 'function') body = new Uint8Array((zlib2 as unknown as { zstdDecompressSync(b: Uint8Array): Buffer }).zstdDecompressSync(body));
				else if (enc.includes('br')) body = new Uint8Array(zlib2.brotliDecompressSync(body));
				else if (enc.includes('gzip')) body = new Uint8Array(zlib2.gunzipSync(body));
				else if (enc.includes('deflate')) body = new Uint8Array(zlib2.inflateSync(body));
			} catch { /* as-is */ }
			const headers = new Headers();
			for (const [k, v] of Object.entries(r.headers)) { if (k === 'content-encoding' || k === 'content-length') continue; for (const one of Array.isArray(v) ? v : [v]) headers.append(k, one); }
			const ab = body.length ? (body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) as ArrayBuffer) : null;
			return new Response(ab, { status: r.status, statusText: '', headers });
		} finally {
			conn.close();
		}
	}
	const tls = await openConnection(open);
	if (init.signal) init.signal.addEventListener('abort', () => tls.close(), { once: true });

	// HTTP/2: use the existing (buffered) h2 path, wrapped as a Response.
	if (useH2 && tls.alpn === 'h2') {
		const headers = { ...(P ? personaHeaders(P) : {}), ...toHeaderObject(init.headers) };
		try {
			const r = await h2Request(tls, { method, authority: u.port ? `${host}:${u.port}` : host, path: u.pathname + u.search, headers, body: bodyBytes }, P?.h2Profile);
			const h2body = r.body.length ? (r.body.buffer.slice(r.body.byteOffset, r.body.byteOffset + r.body.byteLength) as ArrayBuffer) : null;
			return new Response(h2body, { status: r.status, statusText: r.statusText, headers: flatHeaders(r.headers) });
		} finally {
			tls.close();
		}
	}

	// HTTP/1.1 streaming.
	const userHeaders = toHeaderObject(init.headers);
	const reqHeaders: Record<string, string> = {
		Host: u.port ? `${host}:${u.port}` : host,
		...(P ? personaHeaders(P) : { 'User-Agent': 'bun-tls/0.1', Accept: '*/*', 'Accept-Encoding': 'gzip, deflate, br, zstd' }),
		...userHeaders,
		Connection: 'close'
	};
	if (bodyBytes && bodyBytes.length) reqHeaders['Content-Length'] = String(bodyBytes.length);
	tls.writeApp(serializeRequest({ method, host, path: u.pathname + u.search, headers: reqHeaders, body: bodyBytes }));

	// Read the response head, then stream the body.
	let buf: Uint8Array = new Uint8Array(0);
	let headEnd = -1;
	while (headEnd < 0) {
		const chunk = await tls.readApp();
		if (chunk === null) {
			tls.close();
			throw new Error('bun-tls fetch: connection closed before response head');
		}
		buf = buf.length ? concat(buf, chunk) : chunk;
		headEnd = indexOfHeadEnd(buf);
	}
	const headStr = Buffer.from(buf.subarray(0, headEnd)).toString('latin1');
	const [statusLine, ...rest] = headStr.split('\r\n');
	const m = /^HTTP\/1\.[01] (\d{3}) ?(.*)$/.exec(statusLine!);
	if (!m) {
		tls.close();
		throw new Error('bun-tls fetch: malformed status line');
	}
	const status = Number(m[1]);
	const statusText = m[2] ?? '';
	const headers = new Headers();
	for (const line of rest) {
		const i = line.indexOf(':');
		if (i > 0) headers.append(line.slice(0, i).trim(), line.slice(i + 1).trim());
	}
	const leftover = buf.subarray(headEnd + 4);
	const te = (headers.get('transfer-encoding') ?? '').toLowerCase();
	const clRaw = headers.get('content-length');
	const chunked = te.includes('chunked');
	const enc = (headers.get('content-encoding') ?? '').toLowerCase();
	const noBody = method === 'HEAD' || status === 204 || status === 304 || (status >= 100 && status < 200);

	if (noBody) {
		tls.close();
		headers.delete('content-encoding');
		return new Response(null, { status, statusText, headers });
	}
	const stream = bodyStream(tls, leftover, chunked, clRaw != null && !chunked ? Number(clRaw) : null, enc, () => tls.close());
	// content-encoding/length no longer describe the (decoded, streamed) body we expose.
	if (enc) headers.delete('content-encoding');
	headers.delete('content-length');
	return new Response(stream, { status, statusText, headers });
}

function flatHeaders(h: Record<string, string | string[]>): Headers {
	const out = new Headers();
	for (const [k, v] of Object.entries(h)) {
		if (k.toLowerCase() === 'content-encoding' || k.toLowerCase() === 'content-length') continue;
		for (const one of Array.isArray(v) ? v : [v]) out.append(k, one);
	}
	return out;
}
