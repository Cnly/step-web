import test from 'node:test';
import assert from 'node:assert/strict';

import { authenticate } from '../src/auth.js';

const config = {
  issuer: 'https://id.example.test',
  clientId: 'step-web',
  redirectUri: 'https://web.example.test/enroll',
  scope: 'openid email',
};

function storage() {
  const data = new Map();

  return {
    getItem: key => data.get(key) ?? null,
    setItem: (key, value) => data.set(key, String(value)),
    removeItem: key => data.delete(key),
    key: index => [...data.keys()][index] ?? null,
    get length() {
      return data.size;
    },
  };
}

function env(store, url, navigations, replacements) {
  return {
    storage: store,
    url,
    navigate: next => navigations.push(next),
    replaceUrl: next => replacements.push(next),
  };
}

function jwt(claims) {
  const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');

  return `${encode({ alg: 'ES256', typ: 'JWT' })}.${encode(claims)}.signature`;
}

async function start(store, fetchImpl, settings = config) {
  const previous = globalThis.fetch;
  globalThis.fetch = fetchImpl;
  const navigations = [];

  try {
    await authenticate(settings, env(store, settings.redirectUri, navigations, []));

    return new URL(navigations[0]);
  } finally {
    globalThis.fetch = previous;
  }
}

function provider(tokenFactory) {
  return async (url, options) => {
    if (url === 'https://id.example.test/.well-known/openid-configuration') {
      return Response.json({
        issuer: config.issuer,
        authorization_endpoint: 'https://id.example.test/auth',
        token_endpoint: 'https://id.example.test/token',
      });
    }

    if (url === 'https://id.example.test/token') {
      const body = new URLSearchParams(options.body);

      assert.equal(body.get('grant_type'), 'authorization_code');
      assert.equal(body.get('redirect_uri'), config.redirectUri);
      assert.ok(body.get('code_verifier'));

      return Response.json({
        access_token: 'unused-access-token',
        token_type: 'Bearer',
        expires_in: 300,
        id_token: tokenFactory(body),
      });
    }

    throw new Error(`Unexpected provider URL: ${url}`);
  };
}

test('fresh visit starts one code/PKCE S256 request with a nonce and session-only transaction', async () => {
  const store = storage();
  const navigations = [];
  const replacements = [];

  const oldFetch = globalThis.fetch;
  globalThis.fetch = async url => {
    assert.equal(url, 'https://id.example.test/.well-known/openid-configuration');

    return Response.json({
      issuer: config.issuer,
      authorization_endpoint: 'https://id.example.test/auth',
      token_endpoint: 'https://id.example.test/token',
    });
  };

  try {
    assert.equal(
      await authenticate(config, env(store, config.redirectUri, navigations, replacements)),
      null,
    );

    const request = new URL(navigations[0]);
    assert.equal(request.origin, 'https://id.example.test');
    assert.equal(request.searchParams.get('response_type'), 'code');
    assert.equal(request.searchParams.get('code_challenge_method'), 'S256');
    assert.ok(request.searchParams.get('code_challenge'));
    assert.ok(request.searchParams.get('nonce'));
    assert.ok(request.searchParams.get('state'));

    assert.equal(replacements.length, 0);
    assert.equal(store.length, 1);
  } finally {
    globalThis.fetch = oldFetch;
  }
});

test('callbacks without query state fail without network access or a redirect loop', async () => {
  const previous = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => {
    calls++;
    throw new Error('network should not be called');
  };

  try {
    for (const suffix of ['?code=auth-code', '?id_token=forged', '#code=auth-code&state=x']) {
      const navigations = [];
      const replacements = [];

      await assert.rejects(
        authenticate(
          config,
          env(storage(), `${config.redirectUri}${suffix}`, navigations, replacements),
        ),
      );

      assert.deepEqual(navigations, []);
      assert.deepEqual(replacements, [config.redirectUri]);
    }
  } finally {
    globalThis.fetch = previous;
  }

  assert.equal(calls, 0);
});

test('code exchange supports an optional client secret and consumes transaction state', async () => {
  for (const clientSecret of [undefined, '', ' compatibility:+&= value ']) {
    const settings = { ...config, clientSecret };
    const store = storage();
    const requests = [];
    const fetched = provider(body => {
      requests.push(body);

      return jwt({
        iss: config.issuer,
        aud: config.clientId,
        sub: 'alice',
        email: 'alice@example.test',
        exp: Math.floor(Date.now() / 1000) + 300,
        iat: Math.floor(Date.now() / 1000),
        nonce: request.searchParams.get('nonce'),
      });
    });

    const request = await start(store, fetched, settings);
    assert.equal(request.searchParams.has('client_secret'), false);
    assert.equal(request.searchParams.get('code_challenge_method'), 'S256');

    const url = `${config.redirectUri}?code=auth-code&state=${request.searchParams.get('state')}`;
    const replacements = [];
    const previous = globalThis.fetch;
    globalThis.fetch = fetched;

    try {
      const result = await authenticate(settings, env(store, url, [], replacements));

      assert.equal(requests.length, 1);
      assert.equal(requests[0].get('client_secret'), clientSecret || null);

      assert.equal(result.subject, 'alice');
      assert.equal(result.email, 'alice@example.test');
      assert.ok(result.idToken);

      assert.deepEqual(replacements, [config.redirectUri]);
      assert.equal(store.length, 0);

      await assert.rejects(
        authenticate(settings, env(store, url, [], [])),
      );
    } finally {
      globalThis.fetch = previous;
    }
  }
});

test('keeps nonce binding while delegating token validity to step-ca', async () => {
  for (const override of [
    { nonce: 'attacker' },
    { iss: 'https://attacker.example.test' },
    { aud: 'attacker-client' },
    { exp: Math.floor(Date.now() / 1000) - 1 },
    { iat: Math.floor(Date.now() / 1000) + 3600 },
    { azp: 'another-client' },
  ]) {
    const store = storage();
    const request = await start(store, provider(() => 'unused'));
    const token = jwt({
      iss: config.issuer,
      aud: config.clientId,
      sub: 'alice',
      exp: Math.floor(Date.now() / 1000) + 300,
      iat: Math.floor(Date.now() / 1000),
      nonce: request.searchParams.get('nonce'),
      ...override,
    });

    const fetched = provider(() => token);
    const previous = globalThis.fetch;
    globalThis.fetch = fetched;

    try {
      const result = authenticate(
        config,
        env(
          store,
          `${config.redirectUri}?code=auth-code&state=${request.searchParams.get('state')}`,
          [],
          [],
        ),
      );

      if (override.nonce) {
        await assert.rejects(result);
      } else {
        assert.deepEqual(await result, { idToken: token, subject: 'alice' });
      }

      assert.equal(store.length, 0);
    } finally {
      globalThis.fetch = previous;
    }
  }
});

test('expired transaction fails without network access or a redirect loop', async () => {
  const store = storage();
  const request = await start(store, provider(() => 'unused'));

  const key = store.key(0);
  const state = JSON.parse(store.getItem(key));
  state.created -= 601;
  store.setItem(key, JSON.stringify(state));

  const callback = `${config.redirectUri}?code=auth-code&state=${request.searchParams.get('state')}`;
  const previous = globalThis.fetch;
  const navigations = [];
  let calls = 0;
  globalThis.fetch = async () => {
    calls++;
    throw new Error('network should not be called');
  };

  try {
    await assert.rejects(
      authenticate(config, env(store, callback, navigations, [])),
    );

    assert.equal(store.length, 0);
    assert.equal(calls, 0);
    assert.deepEqual(navigations, []);
  } finally {
    globalThis.fetch = previous;
  }
});

test('local development permits configured loopback HTTP endpoints and redirect', async () => {
  const local = {
    ...config,
    issuer: 'http://localhost:4174',
    redirectUri: 'http://localhost:4173/enroll',
  };

  const oldFetch = globalThis.fetch;
  globalThis.fetch = async url => {
    assert.equal(url, 'http://localhost:4174/.well-known/openid-configuration');

    return Response.json({
      issuer: local.issuer,
      authorization_endpoint: 'http://localhost:4174/auth',
      token_endpoint: 'http://localhost:4174/token',
    });
  };
  const navigations = [];

  try {
    assert.equal(
      await authenticate(local, env(storage(), local.redirectUri, navigations, [])),
      null,
    );

    const request = new URL(navigations[0]);
    assert.equal(request.origin, 'http://localhost:4174');
    assert.equal(request.searchParams.get('redirect_uri'), local.redirectUri);
  } finally {
    globalThis.fetch = oldFetch;
  }
});

test('unknown state and a fresh provider error fail before discovery or token exchange', async () => {
  const store = storage();
  const request = await start(store, provider(() => 'unused'));

  const previous = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => {
    calls++;
    throw new Error('network should not be called');
  };

  try {
    await assert.rejects(
      authenticate(
        config,
        env(store, `${config.redirectUri}?code=auth-code&state=unknown`, [], []),
      ),
    );

    assert.equal(store.length, 1);

    await assert.rejects(
      authenticate(
        config,
        env(
          store,
          `${config.redirectUri}?error=access_denied&state=${request.searchParams.get('state')}`,
          [],
          [],
        ),
      ),
    );

    assert.equal(store.length, 0);
    assert.equal(calls, 0);
  } finally {
    globalThis.fetch = previous;
  }
});
