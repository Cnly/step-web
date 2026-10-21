import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { webcrypto } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { createIdentity, createPkcs12 } from '../src/identity.js';

if (process.platform !== 'darwin') {
  console.log('Apple import probe skipped: macOS required');
  process.exit(0);
}

const openssl = process.env.OPENSSL ?? 'openssl';
const dir = mkdtempSync(join(tmpdir(), 'step-web-apple-'));
const project = dirname(dirname(fileURLToPath(import.meta.url)));

const pem = (label, der) =>
  `-----BEGIN ${label}-----\n${Buffer.from(der).toString('base64').match(/.{1,64}/g).join('\n')}\n-----END ${label}-----\n`;

try {
  const identity = await createIdentity('apple-probe@example.test');

  const csr = join(dir, 'leaf.csr');
  const key = join(dir, 'leaf.key');
  const cert = join(dir, 'leaf.crt');
  const extensions = join(dir, 'client.ext');

  writeFileSync(csr, identity.csrPem);
  writeFileSync(
    key,
    pem('PRIVATE KEY', await webcrypto.subtle.exportKey('pkcs8', identity.privateKey)),
  );
  writeFileSync(
    extensions,
    'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n',
  );

  execFileSync(openssl, [
    'x509', '-req', '-in', csr, '-signkey', key,
    '-days', '1', '-out', cert, '-extfile', extensions,
  ]);
  const certificateChainPem = [readFileSync(cert, 'utf8')];

  for (const [label, password] of [
    ['ASCII', 'TestPassword1234'],
    ['Unicode', '咖啡和猫123!'],
  ]) {
    const p12 = await createPkcs12({
      ...identity,
      certificateChainPem,
      password,
      friendlyName: 'Apple probe',
    });

    const path = join(dir, 'ec-identity.p12');
    writeFileSync(path, p12);

    const output = execFileSync('/usr/bin/swift', [
      '-module-cache-path', join(dir, 'swift-cache'),
      '-Xcc', `-fmodules-cache-path=${join(dir, 'clang-cache')}`,
      join(project, 'test/apple-import.swift'), password, path,
    ], { encoding: 'utf8' });

    assert.match(output, /IMPORT_OK identity=yes privateKey=yes signVerify=ok/);
    console.log(`${label}: ${output.trim()}`);
  }
} finally {
  rmSync(dir, { recursive: true, force: true });
}
