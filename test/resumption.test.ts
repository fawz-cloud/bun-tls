// Resumption + 0-RTT key schedule vs RFC 8448 §4 "Resumed 0-RTT Handshake" vectors
// (cipher TLS_AES_128_GCM_SHA256). Validates early_secret, binder, the PSK binder,
// client_early_traffic_secret, and the early-data write key/iv — byte for byte.
import assert from 'node:assert';
import { fromHex, hex } from '../src/core/bytes';
import { sha, expandLabel, earlySecret, binderKey, pskBinder, clientEarlyTraffic, trafficKey } from '../src/core/crypto';

// The resumption ClientHello (512 octets, with binder), line-grouped from the RFC so
// transcription is checkable against the published transcript hash.
const CH = fromHex(
	[
		'010001fc03031bc3ceb6bbe39cff',
		'938355b5a50adb6db21b7a6af649d7b4bc419d7876',
		'487d95000006130113031302010001cd0000000b00',
		'09000006736572766572ff01000100000a00140012',
		'001d00170018001901000101010201030104003300',
		'260024001d0020e4ffb68ac05f8d96c99da2669834',
		'6c6be16482badddafe051a66b4f18d668f0b002a00',
		'00002b0003020304000d0020001e04030503060302',
		'030804080508060401050106010201040205020602',
		'0202002d00020101001c0002400100150057000000',
		'000000000000000000000000000000000000000000',
		'000000000000000000000000000000000000000000',
		'000000000000000000000000000000000000000000',
		'000000000000000000000000000000000000000000',
		'002900dd00b800b22c035d829359ee5ff7af4ec900',
		'000000262a6494dc486d2c8a34cb33fa90bf1b0070',
		'ad3c498883c9367c09a2be785abc55cd226097a3a9',
		'82117283f82a03a143efd3ff5dd36d64e861be7fd6',
		'1d2827db279cce145077d454a3664d4e6da4d29ee0',
		'3725a6a4dafcd0fc67d2aea70529513e3da2677fa5',
		'906c5b3f7d8f92f228bda40dda721470f9fbf297b5',
		'aea617646fac5c03272e970727c621a79141ef5f7d',
		'e6505e5bfbc388e93343694093934ae4d357fad6aa',
		'cb0021203add4fb2d8fdf822a0ca3cf7678ef5e88d',
		'ae990141c5924d57bb6fa31b9e5f9d'
	].join('')
);
const PREFIX = CH.subarray(0, CH.length - 35); // drop "00 21 20" + 32-byte binder
const PSK = fromHex('4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3');
const h = 'sha256' as const;

assert.equal(hex(sha(h, CH)), '08ad0fa05d7c7233b1775ba2ff9f4c5b8b59276b7f227f13a976245f5d960913', 'CH transcript hash');
assert.equal(hex(sha(h, PREFIX)), '63224b2e4573f2d3454ca84b9d009a04f6be9e05711a8396473aefa01e924a14', 'CH prefix hash');

const early = earlySecret(h, PSK);
assert.equal(hex(early), '9b2188e9b2fc6d64d71dc329900e20bb41915000f678aa839cbb797cb7d8332c', 'early_secret');

const bKey = binderKey(h, early);
assert.equal(hex(bKey), '69fe131a3bbad5d63c64eebcc30e395b9d8107726a13d074e389dbc8a4e47256', 'binder_key');
assert.equal(hex(expandLabel(h, bKey, 'finished', new Uint8Array(0), 32)), '5588673e72cb59c87d220caffe94f2dea9a3b1609f7d50e90a48227db9ed7eaa', 'finished_key');
assert.equal(hex(pskBinder(h, bKey, PREFIX)), '3add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d', 'PSK binder');

const cet = clientEarlyTraffic(h, early, CH);
assert.equal(hex(cet), '3fbbe6a60deb66c30a32795aba0eff7eaa10105586e7be5c09678d63b6caab62', 'client_early_traffic_secret');

const tk = trafficKey(h, cet, 16);
assert.equal(hex(tk.key), '920205a5b7bf2115e6fc5c2942834f54', 'early write key');
assert.equal(hex(tk.iv), '6d475f0993c8e564610db2b9', 'early write iv');

console.log('resumption: OK');
