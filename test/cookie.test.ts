// Public Suffix List + cookie jar rules (offline).
import assert from 'node:assert';
import { publicSuffix, registrableDomain, isPublicSuffix } from '../src/http/psl';
import { Session } from '../src/http/session';

assert.equal(publicSuffix('www.example.co.uk'), 'co.uk', 'ps co.uk');
assert.equal(registrableDomain('www.example.co.uk'), 'example.co.uk', 'registrable example.co.uk');
assert.equal(isPublicSuffix('co.uk'), true, 'co.uk is a public suffix');
assert.equal(isPublicSuffix('com'), true, 'com is a public suffix');
assert.equal(isPublicSuffix('example.com'), false, 'example.com is not a public suffix');
assert.equal(registrableDomain('a.b.example.com'), 'example.com', 'registrable example.com');
assert.equal(publicSuffix('foo.github.io'), 'github.io', 'github.io (private wildcard-style entry)');

const s = new Session();
const u = new URL('https://www.example.co.uk/');
s.cookies.setFromHeader(
	['super=1; Domain=co.uk', 'ok=2; Domain=example.co.uk', 'host=3', '__Host-a=4', '__Host-b=5; Secure; Path=/'],
	u
);
const h = s.cookies.header(u);
assert.ok(!h.includes('super=1'), 'supercookie Domain=co.uk rejected');
assert.ok(h.includes('ok=2'), 'registrable-domain cookie kept');
assert.ok(h.includes('host=3'), 'host-only cookie kept');
assert.ok(!h.includes('__Host-a=4'), '__Host- without Secure rejected');
assert.ok(h.includes('__Host-b=5'), '__Host- with Secure + Path=/ kept');

console.log('cookie: OK');
