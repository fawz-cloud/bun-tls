// Worker side of SessionPool: one Session per worker. Receives an init message with the
// Session options, then {req} messages; runs each request and posts the response back, with the
// body's ArrayBuffer transferred (zero-copy). Only serializable options cross the boundary — a
// persona is a name, never a Persona/Fingerprint object (those carry functions).
import { Session } from './session';
import type { SessionOptions } from './session';

declare const self: Worker;
const post = (m: unknown, transfer: ArrayBuffer[] = []) => (self as unknown as { postMessage: (m: unknown, t: ArrayBuffer[]) => void }).postMessage(m, transfer);

interface WReq {
	id: number;
	url: string;
	method?: string;
	headers?: Record<string, string>;
	body?: ArrayBuffer;
	http2?: boolean;
}

let session: Session | null = null;

self.onmessage = async (e: MessageEvent) => {
	const msg = e.data as { t: string } & Record<string, unknown>;
	if (msg.t === 'init') {
		session = new Session(msg.opts as SessionOptions);
		post({ t: 'ready' });
		return;
	}
	if (msg.t === 'close') {
		session?.close();
		post({ t: 'closed' });
		return;
	}
	if (msg.t === 'req') {
		const req = msg as unknown as WReq;
		try {
			const r = await session!.request({ url: req.url, method: req.method, headers: req.headers, body: req.body ? new Uint8Array(req.body) : undefined, http2: req.http2 });
			// body is an exact-size buffer (http1 join / h2 concat), so transfer it straight.
			const body = r.body.byteOffset === 0 && r.body.buffer.byteLength === r.body.length ? r.body.buffer : r.body.slice().buffer;
			post(
				{
					t: 'res',
					id: req.id,
					res: { status: r.status, statusText: r.statusText, headers: r.headers, reusable: r.reusable, ja3: r.ja3, ja3Hash: r.ja3Hash, ja3n: r.ja3n, ja3nHash: r.ja3nHash, ja4: r.ja4, alpn: r.alpn, body }
				},
				[body as ArrayBuffer]
			);
		} catch (err) {
			post({ t: 'err', id: req.id, err: { name: (err as Error)?.name ?? 'Error', message: (err as Error)?.message ?? String(err) } });
		}
	}
};
