// Offline X.509 constraint tests (RFC 5280). Fixtures in test/fixtures/x509 are public
// certs (no private keys) generated with OpenSSL; each bad chain is one OpenSSL reject
// (`openssl verify -purpose sslserver`), each good one an OpenSSL accept.
import assert from 'node:assert';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { enforceConstraints } from '../src/tls/x509';

const dir = join(import.meta.dir, 'fixtures', 'x509');
const C = (f: string) => new crypto.X509Certificate(readFileSync(join(dir, f + '.pem')));
const root = C('root');
const root2 = C('root2');
const run = (chain: crypto.X509Certificate[]) => enforceConstraints(chain, chain.length - 1);

// A good leaf (serverAuth, SAN localhost) under the root passes.
assert.doesNotThrow(() => run([C('good_leaf'), root]), 'good chain accepted');

// Each of the four constraints Node/OpenSSL enforce must reject here too.
assert.throws(() => run([C('eku_leaf'), root]), /serverAuth/, 'leaf EKU clientAuth-only rejected');
assert.throws(() => run([C('crit_leaf'), root]), /critical/, 'unknown critical extension rejected');
assert.throws(() => run([C('nc_leaf'), C('nc_int'), root]), /NameConstraints/, 'excluded NameConstraints subtree rejected');
assert.throws(() => run([C('pl0_leaf'), C('pl0_sub'), C('pl0_int'), root]), /pathLen/, 'pathLenConstraint violation rejected');

// EKU chaining: an intermediate whose EKU lacks serverAuth cannot issue server certs.
assert.throws(() => run([C('ekuc_leaf'), C('ekuc_int'), root2]), /intermediate certificate .*serverAuth/, 'intermediate EKU clientAuth-only rejected');
assert.doesNotThrow(() => run([C('ekus_leaf'), C('ekus_int'), root2]), 'intermediate EKU with serverAuth accepted');

// NameConstraints beyond DNS/IP: email (rfc822Name), directoryName, URI.
assert.throws(() => run([C('nce_bad'), C('nce_int'), root2]), /email a@evil\.com/, 'email outside the permitted subtree rejected');
assert.doesNotThrow(() => run([C('nce_ok'), C('nce_int'), root2]), 'email inside the permitted subtree accepted');
assert.doesNotThrow(() => run([C('nce_none'), C('nce_int'), root2]), 'email constraints do not touch a leaf without email');
assert.throws(() => run([C('ncd_bad'), C('ncd_int'), root2]), /directory name/, 'subject DN outside the permitted directoryName rejected');
assert.doesNotThrow(() => run([C('ncd_ok'), C('ncd_int'), root2]), 'subject DN inside the permitted directoryName accepted');
assert.throws(() => run([C('ncu_bad'), C('ncu_int'), root2]), /URI/, 'URI outside the permitted subtree rejected');

// Host matching ignores the subject CN (SAN only): a CN-only leaf names no host.
assert.equal(C('cn_only').checkHost('localhost', { subject: 'never' }), undefined, 'CN-only leaf does not match by CN');

console.log('x509: OK');
