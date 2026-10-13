// Offline X.509 constraint tests (RFC 5280). Fixtures in test/fixtures/x509 are public
// certs (no private keys) generated with OpenSSL; each bad chain is one Node/OpenSSL reject.
import assert from 'node:assert';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { enforceConstraints } from '../src/tls/x509';

const dir = join(import.meta.dir, 'fixtures', 'x509');
const C = (f: string) => new crypto.X509Certificate(readFileSync(join(dir, f + '.pem')));
const root = C('root');
const run = (chain: crypto.X509Certificate[]) => enforceConstraints(chain, chain.length - 1);

// A good leaf (serverAuth, SAN localhost) under the root passes.
assert.doesNotThrow(() => run([C('good_leaf'), root]), 'good chain accepted');

// Each of the four constraints Node/OpenSSL enforce must reject here too.
assert.throws(() => run([C('eku_leaf'), root]), /serverAuth/, 'leaf EKU clientAuth-only rejected');
assert.throws(() => run([C('crit_leaf'), root]), /critical/, 'unknown critical extension rejected');
assert.throws(() => run([C('nc_leaf'), C('nc_int'), root]), /NameConstraints/, 'excluded NameConstraints subtree rejected');
assert.throws(() => run([C('pl0_leaf'), C('pl0_sub'), C('pl0_int'), root]), /pathLen/, 'pathLenConstraint violation rejected');

console.log('x509: OK');
