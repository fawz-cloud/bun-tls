// SessionPool: N Bun Workers, each with its own Session, requests round-robined across them.
// This is how bun-tls scales past one CPU core — a single Session saturates one core at ~39k
// req/s, and the postMessage round-trip (~3 µs amortized) is far cheaper than a request's TLS
// work, so throughput scales with the worker count. Each worker keeps its OWN cookie jar,
// keep-alive pool and tickets, so a pool is for stateless high-throughput fan-out, not for a
// flow that depends on shared cookies. Streaming, fetch() and WebSocket are not routed here.
import type { SessionOptions } from './session';
import type { HttpResponse } from './http1';

export interface PoolOptions extends Omit<SessionOptions, 'fingerprint' | 'persona'> {
	/** Number of workers (default: navigator.hardwareConcurrency, capped at 8). */
	workers?: number;
	/** Persona by NAME only ('chrome'|'edge'|'firefox'|'safari'); a Persona object can't cross a
	 *  worker boundary (it carries functions). A Fingerprint object is rejected for the same reason. */
	persona?: string;
}

export interface PoolRequest {
	url: string;
	method?: string;
	headers?: Record<string, string>;
	body?: string | Uint8Array;
	http2?: boolean;
}

export interface PoolResponse extends HttpResponse {
	ja3: string;
	ja3Hash: string;
	ja3n: string;
	ja3nHash: string;
	ja4: string;
	alpn: string | null;
}

interface Pending {
	resolve: (r: PoolResponse) => void;
	reject: (e: Error) => void;
}

const WORKER_URL = new URL('./pool-worker.ts', import.meta.url).href;
// Shared lazy body accessors (one closure pair for the whole pool, not per response).
function text(this: PoolResponse): string {
	return Buffer.from(this.body.buffer, this.body.byteOffset, this.body.length).toString('utf8');
}
function json<T>(this: PoolResponse): T {
	return JSON.parse(this.text()) as T;
}

export class SessionPool {
	private workers: Worker[] = [];
	private ready: Promise<void>[] = [];
	private readyResolve: (() => void)[] = [];
	private readyDone: boolean[] = [];
	private pending = new Map<number, Pending>();
	private rr = 0;
	private id = 0;
	private closed = false;

	constructor(private opts: PoolOptions = {}) {
		if ((opts as { fingerprint?: unknown }).fingerprint) throw new Error('SessionPool: a Fingerprint object cannot cross a worker; use a persona name');
		const n = Math.max(1, opts.workers ?? Math.min(8, (globalThis.navigator?.hardwareConcurrency ?? 4)));
		const { workers: _w, ...sessionOpts } = opts;
		for (let i = 0; i < n; i++) this.spawn(sessionOpts);
	}

	private spawn(sessionOpts: Omit<PoolOptions, 'workers'>, slot = this.workers.length): void {
		const w = new Worker(WORKER_URL);
		let onReady!: () => void;
		this.readyDone[slot] = false;
		this.ready[slot] = new Promise<void>((res) => (onReady = res));
		this.readyResolve[slot] = onReady; // so close() can release requests queued on a not-yet-ready worker
		w.onmessage = (e: MessageEvent) => {
			const m = e.data as { t: string; id?: number; res?: Record<string, unknown> & { body: ArrayBuffer }; err?: { name: string; message: string } };
			if (m.t === 'ready') {
				this.readyDone[slot] = true;
				return onReady();
			}
			if (m.t === 'res') this.settle(m.id!, m.res!, null);
			else if (m.t === 'err') this.settle(m.id!, null, m.err!);
		};
		w.onerror = () => this.replaceWorker(slot, sessionOpts); // a worker crash fails its in-flight requests
		w.postMessage({ t: 'init', opts: sessionOpts });
		this.workers[slot] = w;
	}

	private replaceWorker(slot: number, sessionOpts: Omit<PoolOptions, 'workers'>): void {
		if (this.closed) return;
		try {
			this.workers[slot]?.terminate();
		} catch {
			/* already gone */
		}
		// Reject everything still outstanding (we can't know which belonged to this worker; the
		// caller retries idempotent work). Then bring a fresh worker up in its place.
		for (const [id, p] of this.pending) {
			p.reject(new Error('SessionPool worker crashed'));
			this.pending.delete(id);
		}
		this.spawn(sessionOpts, slot);
	}

	private settle(id: number, res: (Record<string, unknown> & { body: ArrayBuffer }) | null, err: { name: string; message: string } | null): void {
		const p = this.pending.get(id);
		if (!p) return;
		this.pending.delete(id);
		if (err) {
			const e = new Error(err.message);
			e.name = err.name;
			return p.reject(e);
		}
		// Minimal main-thread work: wrap the transferred buffer and hand the worker's object back
		// as-is (text/json read from it lazily). Every field the worker sent is already there.
		res!.body = new Uint8Array(res!.body) as unknown as ArrayBuffer;
		const r = res as unknown as PoolResponse;
		r.text = text;
		r.json = json;
		p.resolve(r);
	}

	request(req: PoolRequest): Promise<PoolResponse> {
		if (this.closed) return Promise.reject(new Error('SessionPool is closed'));
		const slot = this.rr++ % this.workers.length;
		const id = ++this.id;
		const body = req.body === undefined ? undefined : typeof req.body === 'string' ? (new TextEncoder().encode(req.body).buffer as ArrayBuffer) : (req.body.slice().buffer as ArrayBuffer);
		const send = () =>
			new Promise<PoolResponse>((resolve, reject) => {
				if (this.closed) return reject(new Error('SessionPool is closed')); // closed while queued on worker init
				this.pending.set(id, { resolve, reject });
				this.workers[slot]!.postMessage({ t: 'req', id, url: req.url, method: req.method, headers: req.headers, body, http2: req.http2 }, body ? [body] : []);
			});
		// Only pay the await on a worker that hasn't finished init yet; after that, send directly.
		return this.readyDone[slot] ? send() : this.ready[slot]!.then(send);
	}

	get(url: string, opts: Omit<PoolRequest, 'url' | 'method'> = {}): Promise<PoolResponse> {
		return this.request({ ...opts, url, method: 'GET' });
	}
	post(url: string, opts: Omit<PoolRequest, 'url' | 'method'> = {}): Promise<PoolResponse> {
		return this.request({ ...opts, url, method: 'POST' });
	}

	close(): void {
		this.closed = true;
		for (const [id, p] of this.pending) {
			p.reject(new Error('SessionPool closed'));
			this.pending.delete(id);
		}
		// Release any request queued on a worker that never became ready — its send() then sees
		// `closed` and rejects, instead of waiting on a ready promise that will never resolve.
		for (const r of this.readyResolve) r?.();
		for (const w of this.workers) {
			try {
				w.terminate();
			} catch {
				/* already gone */
			}
		}
		this.workers = [];
	}
}
