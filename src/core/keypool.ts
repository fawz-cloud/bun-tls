// Pre-generated, single-use key shares, so building a ClientHello never waits on key
// generation (ML-KEM-768 ~80 µs, X25519 ~15 µs, P-256 ~10 µs) — the others generate keys
// inline at that point. Every key is handed out exactly once: a reused key_share would weaken
// forward secrecy and give observers a tracking handle. The pool refills one key per
// setImmediate, i.e. in the gaps while handshakes wait on the network, and only for groups
// that have been asked for. Keys older than TTL_MS are dropped unused.
import type crypto from 'node:crypto';
import { ecShare, mlkem768Keypair, type KemKey } from './crypto';
import { Group } from './consts';

const DEPTH = 4; // per group; a burst of concurrent dials beyond it generates inline, as before
const TTL_MS = 30_000;

const gens = new Map<number, () => unknown>();
const pools = new Map<number, { v: unknown; t: number }[]>();
let refilling = false;

function take<T>(group: number, gen: () => T): T {
	let pool = pools.get(group);
	if (!pool) {
		pools.set(group, (pool = []));
		gens.set(group, gen);
	}
	const now = Date.now();
	while (pool.length && now - pool[0]!.t > TTL_MS) dispose(pool.shift()!.v);
	const hit = pool.shift(); // oldest first
	if (!refilling) {
		refilling = true;
		setImmediate(refill);
	}
	return hit ? (hit.v as T) : gen();
}

/** Generate ONE key for the first group below DEPTH, then yield; stop when all are full. */
async function refill(): Promise<void> {
	for (const [group, pool] of pools) {
		if (pool.length >= DEPTH) continue;
		try {
			pool.push({ v: await gens.get(group)!(), t: Date.now() });
		} catch {
			refilling = false; // a generator failed: stop refilling, callers generate inline
			return;
		}
		setImmediate(refill);
		return;
	}
	refilling = false;
}

function dispose(v: unknown): void {
	(v as Partial<KemKey>).destroy?.(); // native ML-KEM handle; EC KeyObjects are just GC'd
}

/** A fresh x25519 / secp256r1 / secp384r1 key share. */
export const takeEcShare = (group: number): { priv: crypto.KeyObject; pub: Uint8Array } => take(group, () => ecShare(group));

/** A fresh ML-KEM-768 key pair (for the X25519MLKEM768 hybrid; the X25519 half is a separate
 *  takeEcShare(x25519)). Synchronous on CNG; a Promise on the WebCrypto fallback. */
export const takeMlkem768 = (): KemKey | Promise<KemKey> => take(Group.x25519mlkem768, mlkem768Keypair);
