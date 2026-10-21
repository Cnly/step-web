import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createPrivateKey, webcrypto } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import * as asn1js from 'asn1js';

import { createIdentity, createPkcs12 } from '../src/identity.js';

const openssl = process.env.OPENSSL ?? 'openssl';
const password = 'TestPassword1234';

function pem(label, bytes) {
  const body = Buffer.from(bytes).toString('base64').match(/.{1,64}/g).join('\n');

  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
}

async function withDirectory(run) {
  const dir = mkdtempSync(join(tmpdir(), 'step-web-identity-'));

  try {
    return await run(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

async function issuedCertificate(identity, dir) {
  const csr = join(dir, 'leaf.csr');
  const key = join(dir, 'leaf.key');
  const cert = join(dir, 'leaf.crt');

  writeFileSync(csr, identity.csrPem);
  writeFileSync(
    key,
    pem('PRIVATE KEY', await webcrypto.subtle.exportKey('pkcs8', identity.privateKey)),
  );

  execFileSync(openssl, ['x509', '-req', '-in', csr, '-signkey', key, '-days', '1', '-out', cert]);

  return readFileSync(cert, 'utf8');
}

test('createIdentity returns a signed P-256 CSR with the requested common name', async () => {
  await withDirectory(async dir => {
    const identity = await createIdentity('alice@example.test');

    assert.equal(identity.privateKey.algorithm.namedCurve, 'P-256');
    assert.equal(identity.publicKey.algorithm.namedCurve, 'P-256');

    // OpenSSL accepts an omitted attributes field, but Go/step-ca rejects it.
    const der = Buffer.from(
      identity.csrPem.replace(/-----[^-]+-----/g, '').replace(/\s/g, ''),
      'base64',
    );
    const fields = asn1js.fromBER(der).result.valueBlock.value[0].valueBlock.value;

    assert.equal(fields.length, 4, 'PKCS#10 request info must include attributes');
    assert.equal(fields[3].idBlock.tagClass, 3);
    assert.equal(fields[3].idBlock.tagNumber, 0);
    assert.equal(fields[3].idBlock.isConstructed, true);

    const path = join(dir, 'identity.csr');
    writeFileSync(path, identity.csrPem);

    const output = execFileSync(
      openssl,
      ['req', '-in', path, '-verify', '-noout', '-subject'],
      { encoding: 'utf8' },
    );

    assert.match(output, /CN\s*=\s*alice@example\.test/);
  });
});

test('createPkcs12 preserves the certificate and private key and requires the correct password', async () => {
  await withDirectory(async dir => {
    const identity = await createIdentity('alice@example.test');
    const cert = await issuedCertificate(identity, dir);

    for (const chosenPassword of [password, '', '咖啡和猫123!']) {
      const bundle = await createPkcs12({
        ...identity,
        certificateChainPem: [cert],
        password: chosenPassword,
        friendlyName: 'Alice',
      });

      const path = join(dir, 'identity.p12');
      writeFileSync(path, bundle);

      const decoded = execFileSync(
        openssl,
        ['pkcs12', '-in', path, '-nodes', '-passin', `pass:${chosenPassword}`],
        { encoding: 'utf8' },
      );

      assert.ok(decoded.includes(cert.trim()));
      assert.deepEqual(
        createPrivateKey(decoded).export({ type: 'pkcs8', format: 'der' }),
        Buffer.from(await webcrypto.subtle.exportKey('pkcs8', identity.privateKey)),
      );

      const wrong = spawnSync(
        openssl,
        ['pkcs12', '-in', path, '-nodes', '-passin', 'pass:wrong-password'],
        { encoding: 'utf8' },
      );

      assert.notEqual(wrong.status, 0);
    }
  });
});

test('createPkcs12 rejects a certificate for another public key', async () => {
  await withDirectory(async dir => {
    const first = await createIdentity('first@example.test');
    const other = await createIdentity('other@example.test');
    const cert = await issuedCertificate(other, dir);

    await assert.rejects(
      createPkcs12({
        ...first,
        certificateChainPem: [cert],
        password,
        friendlyName: 'First',
      }),
      /match|public key/i,
    );
  });
});
