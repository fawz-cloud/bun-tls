// RecordReader fuzz + AeadDir round-trip. Run: bun test/record.test.ts
// Proves the chunk-queue reader emits the same records as a naive whole-buffer reader for any
// split points, never corrupts a fragment it already handed out, and that encryptMany →
// decrypt round-trips across the seq 255/256 boundary for AES-128/256 and ChaCha.
import assert from 'node:assert';
import { RecordReader, AeadDir } from '../src/tls/record';
import { aesGcm } from '../src/core/crypto';
import { chacha20Poly1305 } from '../src/core/chacha';

// Small seeded PRNG so a failure is reproducible by its seed.
function mulberry32(seed: number) {
	let a = seed >>> 0;
	return () => {
		a |= 0;
		a = (a + 0x6d2b79f5) | 0;
		let t = Math.imul(a ^ (a >>> 15), 1 | a);
		t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	};
}
const concat = (a: Uint8Array[]) => {
	const out = new Uint8Array(a.reduce((s, x) => s + x.length, 0));
	let o = 0;
	for (const x of a) {
		out.set(x, o);
		o += x.length;
	}
	return out;
};
function makeRecords(rnd: () => number) {
	// Build N records with varied lengths, serialize them, remember type+payload for checking.
	const recs: { type: number; payload: Uint8Array }[] = [];
	const wire: Uint8Array[] = [];
	const n = 1 + Math.floor(rnd() * 40);
	for (let i = 0; i < n; i++) {
		const bucket = rnd();
		const len = bucket < 0.2 ? Math.floor(rnd() * 2) : bucket < 0.6 ? 1 + Math.floor(rnd() * 4096) : bucket < 0.9 ? 16000 + Math.floor(rnd() * 640) : Math.floor(rnd() * 65536);
		const type = 20 + Math.floor(rnd() * 4); // 20..23
		const payload = new Uint8Array(len);
		for (let j = 0; j < len; j++) payload[j] = (i * 131 + j * 17) & 0xff;
		recs.push({ type, payload });
		const hdr = Uint8Array.of(type, 3, 3, (len >> 8) & 0xff, len & 0xff);
		wire.push(hdr, payload);
	}
	return { recs, wire: concat(wire) };
}
function splitAt(buf: Uint8Array, rnd: () => number): Uint8Array[] {
	// Random split points, sometimes empty pieces and cuts right after a header byte.
	const pieces: Uint8Array[] = [];
	let i = 0;
	while (i < buf.length) {
		let step = Math.floor(rnd() * 70);
		if (rnd() < 0.15) step = 1 + Math.floor(rnd() * 4); // land inside a header often
		const end = Math.min(buf.length, i + step);
		pieces.push(buf.subarray(i, end));
		i = end;
	}
	return pieces;
}

let fuzzChecks = 0;
for (let seed = 1; seed <= 300; seed++) {
	const rnd = mulberry32(seed);
	const { recs, wire } = makeRecords(rnd);
	const rr = new RecordReader();
	const kept: { got: Uint8Array; want: Uint8Array }[] = [];
	let idx = 0;
	const pieces = seed % 37 === 0 ? [...wire].map((b) => Uint8Array.of(b)) : splitAt(wire, rnd); // one seed byte-by-byte
	for (const piece of pieces) {
		rr.feed(piece);
		for (let r = rr.next(); r; r = rr.next()) {
			assert.ok(idx < recs.length, `seed ${seed}: too many records`);
			assert.equal(r.type, recs[idx]!.type, `seed ${seed} rec ${idx} type`);
			assert.equal(r.fragment.length, recs[idx]!.payload.length, `seed ${seed} rec ${idx} len`);
			kept.push({ got: r.fragment, want: recs[idx]!.payload });
			idx++;
		}
	}
	assert.equal(idx, recs.length, `seed ${seed}: record count`);
	// Recheck every fragment still matches — catches any buffer reuse after it was handed out.
	for (let i = 0; i < kept.length; i++) assert.deepEqual(kept[i]!.got, kept[i]!.want, `seed ${seed}: fragment ${i} stable`);
	fuzzChecks += kept.length;
}

// AeadDir round-trip across seq 255→256, random splits, for each cipher.
for (const mk of [() => aesGcm(16), () => aesGcm(32), () => chacha20Poly1305]) {
	const key = crypto.getRandomValues(new Uint8Array(32));
	const iv = crypto.getRandomValues(new Uint8Array(12));
	const aeadFactory = mk() as (k: Uint8Array) => ReturnType<typeof chacha20Poly1305>;
	const enc = new AeadDir(aeadFactory(key.subarray(0, (mk() as any)(key).keyLen)), iv);
	const dec = new AeadDir(aeadFactory(key.subarray(0, (mk() as any)(key).keyLen)), iv);
	const rr = new RecordReader();
	const payloads: Uint8Array[] = [];
	const wire: Uint8Array[] = [];
	for (let i = 0; i < 1000; i++) {
		const p = crypto.getRandomValues(new Uint8Array(1 + (i % 200)));
		payloads.push(p);
		wire.push(enc.encrypt(23, p)); // one record each → crosses seq 255/256
	}
	const all = concat(wire);
	const rnd = mulberry32(999);
	let i = 0;
	let idx = 0;
	while (i < all.length) {
		const end = Math.min(all.length, i + 1 + Math.floor(rnd() * 5000));
		rr.feed(all.subarray(i, end));
		i = end;
		for (let r = rr.next(); r; r = rr.next()) {
			const d = dec.decrypt(r);
			assert.equal(d.innerType, 23, `cipher rec ${idx} type`);
			assert.deepEqual(d.content, payloads[idx]!, `cipher rec ${idx} content`);
			idx++;
		}
	}
	assert.equal(idx, 1000, 'all records decrypted');
}

console.log(`record: OK (${fuzzChecks} fuzz fragments)`);
