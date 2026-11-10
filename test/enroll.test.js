import test from 'node:test';
import assert from 'node:assert/strict';

import { enroll, EnrollmentError } from '../src/enroll.js';

const config = {
  redirectUri: 'https://enroll.example.test:8443/client/',
  caSignUrl: 'https://ca.example.org/1.0/sign',
  certificateDuration: '24h',
};

const session = {
  idToken: 'secret-id-token',
  subject: 'user-123',
  email: 'alice@example.test',
};

function harness(overrides = {}) {
  const calls = { copies: [], keys: 0, requests: [], bundles: [], downloads: [] };
  const deps = {
    copy: async password => {
      await Promise.resolve();
      calls.copies.push(password);
    },
    prompt: (_message, password) => password,
    now: () => new Date(2026, 0, 2, 0, 30),
    createIdentity: async commonName => {
      calls.keys++;
      assert.equal(commonName, session.email);

      return { privateKey: 'private', publicKey: 'public', csrPem: 'CSR' };
    },
    fetch: async (url, options) => {
      calls.requests.push({ url, options });

      return new Response(
        JSON.stringify({ certChain: ['leaf-pem', 'intermediate-pem'] }),
        { status: 201 },
      );
    },
    createPkcs12: async options => {
      calls.bundles.push(options);

      return new Uint8Array([1, 2, 3]);
    },
    download: (bytes, filename) => calls.downloads.push({ bytes, filename }),
    ...overrides,
  };

  return { calls, deps };
}

test('cancellation does not generate a key or issue a certificate', async () => {
  const { calls, deps } = harness({ prompt: () => null });

  assert.equal(await enroll(config, session, deps), false);

  assert.equal(calls.keys, 0);
  assert.equal(calls.requests.length, 0);
});

test('signs once with only CSR, ID token and requested lifetime; downloads local bundle', async () => {
  const { calls, deps } = harness({
    prompt: (_message, password) => {
      assert.deepEqual(calls.copies, [password]);

      return password;
    },
  });

  assert.equal(await enroll(config, session, deps), true);

  assert.equal(calls.requests.length, 1);

  const { url, options } = calls.requests[0];
  assert.equal(url, config.caSignUrl);
  assert.deepEqual(JSON.parse(options.body), {
    csr: 'CSR',
    ott: 'secret-id-token',
    notAfter: '24h',
  });
  assert.equal(options.credentials, 'omit');
  assert.equal(options.redirect, 'error');
  assert.equal(options.cache, 'no-store');

  assert.equal(calls.bundles.length, 1);
  assert.deepEqual(calls.bundles[0].certificateChainPem, ['leaf-pem', 'intermediate-pem']);
  assert.match(calls.bundles[0].password, /^[A-Za-z0-9]{16}$/);
  assert.equal(calls.bundles[0].password, calls.copies[0]);
  assert.equal(calls.bundles[0].privateKey, 'private');

  assert.deepEqual(calls.downloads, [{
    bytes: new Uint8Array([1, 2, 3]),
    filename: 'enroll.example.test-2026-01-02.p12',
  }]);
});

test('clipboard failures do not stop enrollment', async () => {
  for (const copy of [
    async () => { throw new DOMException('Blocked', 'NotAllowedError'); },
    () => { throw new TypeError('Clipboard unavailable'); },
  ]) {
    const { calls, deps } = harness({ copy });

    assert.equal(await enroll(config, session, deps), true);
    assert.equal(calls.downloads.length, 1);
  }
});

test('changed passwords stop before key generation or certificate issuance', async () => {
  for (const edit of [
    () => 'My passphrase 123!',
    () => '',
    password => ` ${password}`,
    password => `${password} `,
    password => `${password[0] === 'A' ? 'B' : 'A'}${password.slice(1)}`,
  ]) {
    const { calls, deps } = harness({ prompt: (_message, password) => edit(password) });

    await assert.rejects(enroll(config, session, deps), EnrollmentError);

    assert.equal(calls.keys, 0);
    assert.equal(calls.requests.length, 0);
    assert.equal(calls.bundles.length, 0);
    assert.equal(calls.downloads.length, 0);
  }
});

test('does not expose CA responses or retry failed signing requests', async () => {
  const { calls, deps } = harness({
    fetch: async (url, options) => {
      calls.requests.push({ url, options });

      return new Response('secret-id-token secret-password', { status: 401 });
    },
  });

  await assert.rejects(
    enroll(config, session, deps),
    error => error instanceof EnrollmentError
      && error.message.includes('401')
      && !error.message.includes('secret'),
  );

  assert.equal(calls.requests.length, 1);
  assert.equal(calls.downloads.length, 0);
});

test('rejects missing/oversized certificate chains without creating a bundle', async () => {
  for (const payload of [
    {},
    { certChain: [] },
    { certChain: new Array(9).fill('cert') },
    { certChain: [42] },
  ]) {
    const { calls, deps } = harness({
      fetch: async () => new Response(JSON.stringify(payload)),
    });

    await assert.rejects(enroll(config, session, deps), EnrollmentError);

    assert.equal(calls.bundles.length, 0);
    assert.equal(calls.downloads.length, 0);
  }
});
