// fetch()-compatible entry point: same shape as the global fetch (URL/Request-ish input
// + init), returning a standard Web `Response` with a STREAMING body — plus bun-tls's
// fingerprint control (`persona` / `fingerprint`) in the init. Drop-in for code that
// already calls fetch; the body streams instead of buffering (large downloads, SSE).
// Fetch semantics kept: redirects are followed by default (redirect: 'follow' | 'manual' |
// 'error'), an AbortSignal cancels at any point (already aborted → rejects at once), and a
// truncated body is an error, never a short success. `timeoutMs` (bun-tls extension) is ONE
// budget for the whole exchange, dial through the last body byte.
import zlib from 'node:zlib';
import { Readable } from 'node:stream';
import { openConnection } from './client';
import { serializeRequest } from './http1';
import { h2Request } from './h2';
import { withH2 } from './client';
import { modern } from '../fp/fingerprints';
import { resolvePersona, personaHeaders } from '../fp/personas';
import type { Persona } from '../fp/personas';
import type { Fingerprint } from '../tls/clienthello';
import type { OcspMode } from '../tls/verify';
import type { TlsConn } from '../tls/handshake';
import { abortable } from '../tls/transport';
import { concat } from '../core/bytes';
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
	/** Total budget for the request — dial, response head AND body; expiry rejects (or errors
	 *  the body stream) with a TimeoutError. */
	timeoutMs?: number;
	/** Abort the request (standard AbortSignal). */
	signal?: AbortSignal;
	/** As in fetch: 'follow' (default, up to 20 hops), 'manual' (return the 3xx), 'error'. */
	redirect?: 'follow' | 'manual' | 'error';
}

const REDIRECTS = new Set([301, 302, 303, 307, 308]);
const MAX_REDIRECTS = 20;

function toHeaderObject(h: FetchInit['headers']): Record<string, string> {
	const out: Record<string, string> = {};
	if (!h) return out;
	if (h instanceof Headers) h.forEach((v, k) => (out[k] = v));
	else if (Array.isArray(h)) for (const [k, v] of h) out[k] = v;
	else Object.assign(out, h);
	return out;
}

const withoutHeaders = (h: Record<string, string>, drop: RegExp): Record<string, string> => Object.fromEntries(Object.entries(h).filter(([k]) => !drop.test(k)));

/** A Node decompressor transform for a content-encoding, or null for identity. */
function decompressor(enc: string): zlib.BrotliDecompress | zlib.Gunzip | zlib.Inflate | null {
	if (enc.includes('zstd') && typeof (zlib as { createZstdDecompress?: unknown }).createZstdDecompress === 'function')
		return (zlib as unknown as { createZstdDecompress(): zlib.BrotliDecompress }).createZstdDecompress();
	if (enc.includes('br')) return zlib.createBrotliDecompress();
	if (enc.includes('gzip')) return zlib.createGunzip();
	if (enc.includes('deflate')) return zlib.createInflate();
	return null;
}

/** Decode a buffered body (HTTP/2, HTTP/3) by its content-encoding. */
function decodeBuffered(body: Uint8Array, enc: string): Uint8Array {
	if (enc.includes('zstd') && typeof (zlib as { zstdDecompressSync?: unknown }).zstdDecompressSync === 'function') return new Uint8Array((zlib as unknown as { zstdDecompressSync(b: Uint8Array): Buffer }).zstdDecompressSync(body));
	if (enc.includes('br')) return new Uint8Array(zlib.brotliDecompressSync(body));
	if (enc.includes('gzip')) return new Uint8Array(zlib.gunzipSync(body));
	if (enc.includes('deflate')) return new Uint8Array(zlib.inflateSync(body));
	return body;
}

/** Pull framed (de-chunked) body bytes off the TLS connection as they arrive. The stream
 *  ERRORS — never ends short — when the connection drops before the framing says the body is
 *  complete (Content-Length not reached, chunked without its last chunk), and with the
 *  signal's reason when the request is aborted or times out. `onDone` runs exactly once. */
function bodyStream(tls: TlsConn, leftover: Uint8Array, chunked: boolean, contentLength: number | null, enc: string, signal: AbortSignal, onDone: () => void): ReadableStream<Uint8Array> {
	let buf = leftover;
	let received = 0;
	let chunkState: { need: number; inSize: boolean } = { need: -1, inSize: true };
	let finished = false;
	const done = () => {
		if (!finished) {
			finished = true;
			onDone();
		}
	};

	// A chunked decoder fed incrementally; returns decoded bytes + whether the 0-chunk was seen.
	function pumpChunked(): { out: Uint8Array[]; done: boolean } {
		const out: Uint8Array[] = [];
		for (;;) {
			if (chunkState.inSize) {
				const nl = indexOf(buf, 13, 10);
				if (nl < 0) return { out, done: false };
				const line = Buffer.from(buf.subarray(0, nl)).toString('ascii').split(';')[0]!.trim(); // drop chunk extensions
				if (!/^[0-9a-fA-F]+$/.test(line)) throw new Error(`bun-tls fetch: malformed chunk size "${line.slice(0, 20)}"`);
				const size = parseInt(line, 16);
				buf = buf.subarray(nl + 2);
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
			try {
				for (;;) {
					if (chunked) {
						const { out, done: last } = pumpChunked();
						for (const o of out) if (o.length) controller.enqueue(o);
						if (last) {
							done();
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
							}
							buf = new Uint8Array(0);
						}
						if (received >= contentLength) {
							done();
							controller.close();
							return;
						}
					} else if (buf.length) {
						controller.enqueue(buf);
						buf = new Uint8Array(0);
						return;
					}
					const chunk = await tls.readApp();
					if (chunk === null) {
						if (signal.aborted) throw signal.reason;
						if (contentLength !== null) throw new Error(`bun-tls fetch: response body truncated (${received} of ${contentLength} bytes)`);
						if (chunked) throw new Error('bun-tls fetch: response body truncated (chunked body ended without its last chunk)');
						done(); // no framing: the close IS the end of the body
						controller.close();
						return;
					}
					buf = buf.length ? concat(buf, chunk) : chunk;
				}
			} catch (e) {
				done();
				controller.error(signal.aborted ? signal.reason : e);
			}
		},
		cancel() {
			done();
		}
	});

	if (!decomp) return source;
	// Stage 2: pipe framed bytes through the decompressor (Node transform ↔ web stream). A
	// source error must reach the consumer, which `pipe` alone would swallow (hang).
	const nodeReadable = Readable.fromWeb(source as import('node:stream/web').ReadableStream<Uint8Array>);
	nodeReadable.once('error', (e) => decomp.destroy(e));
	decomp.once('close', () => nodeReadable.destroy()); // consumer cancelled → cancel the source → connection closes
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

/** One hop: dial, send, read the head. `streaming` = the body is still on the wire, and
 *  `hooks.done` runs when it has been fully read, cancelled or failed; `close` drops the
 *  connection now (idempotent). */
async function fetchOnce(
	u: URL,
	method: string,
	userHeaders: Record<string, string>,
	body: Uint8Array | undefined,
	init: FetchInit,
	signal: AbortSignal,
	hooks: { done: () => void }
): Promise<{ res: Response; streaming: boolean; close: () => void }> {
	const host = u.hostname;
	const port = u.port ? Number(u.port) : 443;
	const P = init.persona ? resolvePersona(init.persona) : null;
	const useH2 = init.http2 ?? P?.http2 ?? false;
	const baseFp = init.fingerprint ?? P?.fingerprint();

	if (init.http3) {
		const conn = new QuicConnection(host, port);
		const kill = () => conn.close();
		signal.addEventListener('abort', kill, { once: true });
		try {
			const budget = init.timeoutMs ?? 10000; // QUIC's own loops need a bound; the signal cuts it shorter
			await abortable(conn.connect(budget), signal);
			const hs = { ...(P ? personaHeaders(P) : { 'user-agent': 'bun-tls/0.1' }), ...userHeaders };
			const extra: [string, string][] = [];
			for (const [k, v] of Object.entries(hs)) if (k.toLowerCase() !== 'host') extra.push([k.toLowerCase(), v]);
			const r = await abortable(h3Request(conn, method, u.port ? `${host}:${u.port}` : host, u.pathname + u.search, extra, body, budget), signal);
			const enc = (Array.isArray(r.headers['content-encoding']) ? (r.headers['content-encoding'] as string[]).join(',') : (r.headers['content-encoding'] as string) ?? '').toLowerCase();
			const decoded = decodeBuffered(r.body, enc);
			const ab = decoded.length ? (decoded.buffer.slice(decoded.byteOffset, decoded.byteOffset + decoded.byteLength) as ArrayBuffer) : null;
			return { res: new Response(ab, { status: r.status, statusText: '', headers: flatHeaders(r.headers) }), streaming: false, close: () => conn.close() };
		} finally {
			signal.removeEventListener('abort', kill);
			conn.close();
		}
	}

	const tls = await openConnection({ host, port, proxy: init.proxy, fingerprint: useH2 ? withH2(baseFp ?? modern()) : baseFp, verify: init.verify, ocsp: init.ocsp, tls12: init.tls12, signal });
	const kill = () => tls.close();
	signal.addEventListener('abort', kill, { once: true });
	const release = () => {
		signal.removeEventListener('abort', kill);
		tls.close();
	};
	try {
		// HTTP/2: the existing (buffered) h2 path, wrapped as a Response.
		if (useH2 && tls.alpn === 'h2') {
			const headers = { ...(P ? personaHeaders(P) : {}), ...userHeaders };
			const r = await h2Request(tls, { method, authority: u.port ? `${host}:${u.port}` : host, path: u.pathname + u.search, headers, body }, P?.h2Profile);
			release();
			const h2body = r.body.length ? (r.body.buffer.slice(r.body.byteOffset, r.body.byteOffset + r.body.byteLength) as ArrayBuffer) : null;
			return { res: new Response(h2body, { status: r.status, statusText: r.statusText, headers: flatHeaders(r.headers) }), streaming: false, close: release };
		}

		// HTTP/1.1 streaming.
		const reqHeaders: Record<string, string> = {
			Host: u.port ? `${host}:${u.port}` : host,
			...(P ? personaHeaders(P) : { 'User-Agent': 'bun-tls/0.1', Accept: '*/*', 'Accept-Encoding': 'gzip, deflate, br, zstd' }),
			...userHeaders,
			Connection: 'close'
		};
		if (body && body.length) reqHeaders['Content-Length'] = String(body.length);
		tls.writeApp(serializeRequest({ method, host, path: u.pathname + u.search, headers: reqHeaders, body }));

		// Read the response head (skipping interim 1xx responses such as 103 Early Hints), then
		// stream the body.
		let buf: Uint8Array = new Uint8Array(0);
		let status = 0;
		let statusText = '';
		let headers = new Headers();
		for (;;) {
			let headEnd = indexOfHeadEnd(buf);
			while (headEnd < 0) {
				const chunk = await tls.readApp();
				if (chunk === null) throw new Error('bun-tls fetch: connection closed before response head');
				buf = buf.length ? concat(buf, chunk) : chunk;
				headEnd = indexOfHeadEnd(buf);
			}
			const [statusLine, ...rest] = Buffer.from(buf.subarray(0, headEnd)).toString('latin1').split('\r\n');
			const m = /^HTTP\/1\.[01] (\d{3}) ?(.*)$/.exec(statusLine!);
			if (!m) throw new Error('bun-tls fetch: malformed status line');
			buf = buf.subarray(headEnd + 4);
			status = Number(m[1]);
			statusText = m[2] ?? '';
			headers = new Headers();
			for (const line of rest) {
				const i = line.indexOf(':');
				if (i > 0) headers.append(line.slice(0, i).trim(), line.slice(i + 1).trim());
			}
			if (status === 101) throw new Error('bun-tls fetch: unexpected 101 Switching Protocols');
			if (status < 100 || status > 199) break; // a final response
		}
		const leftover = buf;
		const te = (headers.get('transfer-encoding') ?? '').toLowerCase();
		const clRaw = headers.get('content-length');
		const chunked = te.includes('chunked');
		const enc = (headers.get('content-encoding') ?? '').toLowerCase();
		const noBody = method === 'HEAD' || status === 204 || status === 304;

		if (noBody) {
			release();
			headers.delete('content-encoding');
			return { res: new Response(null, { status, statusText, headers }), streaming: false, close: release };
		}
		const contentLength = clRaw != null && !chunked && /^\d+$/.test(clRaw.trim()) ? Number(clRaw) : null;
		const stream = bodyStream(tls, leftover, chunked, contentLength, enc, signal, () => {
			release();
			hooks.done();
		});
		// content-encoding/length no longer describe the (decoded, streamed) body we expose.
		if (enc) headers.delete('content-encoding');
		headers.delete('content-length');
		return { res: new Response(stream, { status, statusText, headers }), streaming: true, close: release };
	} catch (e) {
		release();
		throw e;
	}
}

/** fetch(input, init) → Response, with a streaming body and fingerprint control. */
export async function fetch(input: string | URL, init: FetchInit = {}): Promise<Response> {
	let url = new URL(typeof input === 'string' ? input : input.href);
	if (url.protocol !== 'https:') throw new Error('bun-tls fetch: only https is supported');
	init.signal?.throwIfAborted(); // already aborted → reject before any I/O (fetch semantics)

	// One controller for the caller's signal and timeoutMs: aborting it closes whatever is in
	// flight and rejects (or errors the body stream) with its reason.
	const ac = new AbortController();
	const user = init.signal;
	const onUser = () => ac.abort(user!.reason);
	user?.addEventListener('abort', onUser, { once: true });
	const timer = init.timeoutMs ? setTimeout(() => ac.abort(new DOMException(`bun-tls fetch: timed out after ${init.timeoutMs} ms`, 'TimeoutError')), init.timeoutMs) : undefined;
	let finished = false;
	const finish = () => {
		if (finished) return;
		finished = true;
		clearTimeout(timer);
		user?.removeEventListener('abort', onUser);
	};

	try {
		let method = (init.method ?? 'GET').toUpperCase();
		let body = init.body == null ? undefined : typeof init.body === 'string' ? new Uint8Array(Buffer.from(init.body)) : init.body instanceof ArrayBuffer ? new Uint8Array(init.body) : init.body;
		let headers = toHeaderObject(init.headers);
		const mode = init.redirect ?? 'follow';
		for (let hop = 0; ; hop++) {
			const hooks = { done: () => {} };
			const { res, streaming, close } = await fetchOnce(url, method, headers, body, init, ac.signal, hooks);
			const location = res.headers.get('location');
			if (mode === 'manual' || !REDIRECTS.has(res.status) || location === null) {
				// The final response: the budget/abort hooks stay live until its body is done.
				if (streaming) hooks.done = finish;
				else finish();
				Object.defineProperty(res, 'url', { value: url.href });
				if (hop > 0) Object.defineProperty(res, 'redirected', { value: true });
				return res;
			}
			close(); // drop the 3xx and its connection
			await res.body?.cancel().catch(() => {});
			if (mode === 'error') throw new TypeError(`bun-tls fetch: redirected (${res.status}) with redirect: "error"`);
			if (hop >= MAX_REDIRECTS) throw new TypeError('bun-tls fetch: too many redirects');
			const next = new URL(location, url);
			if (next.protocol !== 'https:') throw new TypeError(`bun-tls fetch: redirect to ${next.protocol} is not supported (https only)`);
			// 303 → GET (except HEAD); 301/302 turn a POST into a GET — the body goes, with its headers.
			if (res.status === 303 ? method !== 'GET' && method !== 'HEAD' : (res.status === 301 || res.status === 302) && method === 'POST') {
				method = 'GET';
				body = undefined;
				headers = withoutHeaders(headers, /^content-(type|length|encoding|language|location)$/i);
			}
			// Credentials never follow a redirect to another origin.
			if (next.origin !== url.origin) headers = withoutHeaders(headers, /^(authorization|proxy-authorization|cookie)$/i);
			url = next;
		}
	} catch (e) {
		finish();
		throw ac.signal.aborted ? ac.signal.reason : e;
	}
}

function flatHeaders(h: Record<string, string | string[]>): Headers {
	const out = new Headers();
	for (const [k, v] of Object.entries(h)) {
		if (k.toLowerCase() === 'content-encoding' || k.toLowerCase() === 'content-length') continue;
		for (const one of Array.isArray(v) ? v : [v]) out.append(k, one);
	}
	return out;
}
