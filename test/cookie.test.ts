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

// Host-only scope (RFC 6265 §5.3): a cookie with no Domain goes ONLY to the exact host.
const s2 = new Session();
s2.cookies.setFromHeader(['sid=1', '__Host-k=2; Secure; Path=/'], new URL('https://login.example.com/'));
assert.ok(s2.cookies.header(new URL('https://login.example.com/')).includes('sid=1'), 'host-only cookie sent to the exact host');
assert.ok(!s2.cookies.header(new URL('https://child.login.example.com/')).includes('sid=1'), 'host-only cookie NOT sent to a subdomain');
assert.ok(!s2.cookies.header(new URL('https://child.login.example.com/')).includes('__Host-k=2'), '__Host- cookie NOT sent to a subdomain');

// Default-path (RFC 6265 §5.1.4): a cookie with no Path defaults to the request directory.
const s3 = new Session();
s3.cookies.setFromHeader(['p=1'], new URL('https://example.com/app/login'));
assert.ok(s3.cookies.header(new URL('https://example.com/app/x')).includes('p=1'), 'default-path cookie sent within /app');
assert.ok(!s3.cookies.header(new URL('https://example.com/other')).includes('p=1'), 'default-path cookie NOT sent to /other');

console.log('cookie: OK');
