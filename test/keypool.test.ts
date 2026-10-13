// Key-share pool: every share is fresh and handed out once, pooled keys work for ECDHE, and the
// ML-KEM pool interoperates with WebCrypto. Run: bun test/keypool.test.ts
import assert from 'node:assert';
import { takeEcShare, takeMlkem768 } from '../src/core/keypool';
import { ecShare, ecdheShared } from '../src/core/crypto';
import { hex } from '../src/core/bytes';

const tick = () => new Promise((r) => setImmediate(r));
const hexes = new Set<string>();

// x25519 / P-256 / P-384: 40 takes each, interleaved with refill turns — never a repeat.
for (const [group, len] of [[0x1d, 32], [0x17, 65], [0x18, 97]] as const) {
	for (let i = 0; i < 40; i++) {
		const s = takeEcShare(group);
		assert.equal(s.pub.length, len, `group ${group} public value length`);
		if (len > 32) assert.equal(s.pub[0], 4, `group ${group} uncompressed point`);
		const h = hex(s.pub);
		assert.ok(!hexes.has(h), `group ${group}: a key share was handed out twice`);
		hexes.add(h);
		// a pooled key must still agree with a fresh peer (ECDHE symmetric)
		if (i % 10 === 0) {
			const peer = ecShare(group);
			assert.deepEqual(ecdheShared(group, s.priv, peer.pub), ecdheShared(group, peer.priv, s.pub), `group ${group} ECDHE symmetric`);
		}
		if (i % 3 === 0) for (let k = 0; k < 6; k++) await tick(); // let the pool refill
	}
}

// ML-KEM-768 (CNG or WebCrypto): fresh each time, and WebCrypto's encapsulation decapsulates.
const ML = { name: 'ML-KEM-768' } as const;
const eks = new Set<string>();
for (let i = 0; i < 12; i++) {
	const k = await takeMlkem768();
	const h = hex(k.ek);
	assert.ok(!eks.has(h), 'an ML-KEM key was handed out twice');
	eks.add(h);
	const pub = await crypto.subtle.importKey('raw-public' as 'raw', k.ek as unknown as ArrayBuffer, ML, true, ['encapsulateBits'] as never);
	const enc = await crypto.subtle.encapsulateBits(ML, pub);
	assert.deepEqual(await k.decapsulate(new Uint8Array(enc.ciphertext)), new Uint8Array(enc.sharedKey), `ML-KEM pooled key ${i} decapsulates`);
	if (i % 2) for (let t = 0; t < 6; t++) await tick();
}

console.log(`keypool: OK (${hexes.size} EC shares + ${eks.size} ML-KEM keys, all distinct)`);
