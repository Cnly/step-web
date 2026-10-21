import test from 'node:test';
import assert from 'node:assert/strict';

const redirectUri = 'https://web.example.test/enroll';

async function loadPage(config, status = 200, discoveryError) {
  const events = [];
  const stored = new Map();

  const globals = {
    window: {
      isSecureContext: true,
      location: {
        href: redirectUri,
        assign: url => events.push({ type: 'navigate', url }),
      },
      sessionStorage: {
        getItem: key => stored.get(key) ?? null,
        setItem: (key, value) => stored.set(key, value),
        removeItem: key => stored.delete(key),
        key: index => [...stored.keys()][index] ?? null,
        get length() {
          return stored.size;
        },
      },
    },
    document: {
      createElement: tagName => ({ tagName }),
      head: {
        append: element => events.push({ type: 'policy', element: { ...element } }),
      },
    },
    alert: message => events.push({ type: 'alert', message }),
    console: {
      ...console,
      error: (...args) => events.push({ type: 'diagnostic', args }),
    },
    fetch: async url => {
      events.push({ type: url === './config.json' ? 'config' : 'discovery', url });

      if (url === './config.json') return Response.json(config, { status });
      if (url !== `${config.issuer}/.well-known/openid-configuration`)
        throw new Error('Unexpected network request');
      if (discoveryError) throw discoveryError;

      return Response.json({
        issuer: config.issuer,
        authorization_endpoint: new URL('/authorize', config.issuer).href,
        token_endpoint: new URL('/token', config.issuer).href,
      });
    },
  };

  const previous = new Map(
    Object.keys(globals).map(key => [key, Object.getOwnPropertyDescriptor(globalThis, key)]),
  );

  Object.assign(globalThis, globals);

  try {
    await import(`../src/main.js?test=${crypto.randomUUID()}`);

    return events;
  } finally {
    for (const [key, descriptor] of previous) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor);
      else delete globalThis[key];
    }
  }
}

test('runtime config restricts connections before authentication for each deployment', async () => {
  for (const { config, policy } of [
    {
      config: {
        issuer: 'https://id.first.test',
        caSignUrl: 'https://ca.first.test/1.0/sign',
      },
      policy: "connect-src 'self' https://id.first.test https://ca.first.test",
    },
    {
      config: {
        issuer: 'https://ID.second.test:443/tenant',
        caSignUrl: 'http://127.0.0.1:8080/1.0/sign',
        oidcExtraOrigins: ['https://id.second.test', 'https://tokens.second.test'],
      },
      policy: "connect-src 'self' https://id.second.test http://127.0.0.1:8080 https://tokens.second.test",
    },
  ]) {
    const events = await loadPage({ ...config, clientId: 'public-client', redirectUri });

    assert.deepEqual(events.map(event => event.type), ['config', 'policy', 'discovery', 'navigate']);
    assert.deepEqual(events[1].element, {
      tagName: 'meta',
      httpEquiv: 'Content-Security-Policy',
      content: policy,
    });
    assert.equal(events[2].url, `${config.issuer}/.well-known/openid-configuration`);
    assert.equal(new URL(events[3].url).searchParams.get('redirect_uri'), redirectUri);
  }
});

test('missing or invalid runtime config stops before adding policy or authenticating', async () => {
  for (const [config, status] of [
    [{}, 404],
    [
      {
        issuer: 'invalid URL',
        caSignUrl: 'https://ca.example.test/sign',
        clientId: 'public-client',
        redirectUri,
      },
      200,
    ],
  ]) {
    const events = await loadPage(config, status);

    assert.deepEqual(events.map(event => event.type), ['config', 'diagnostic', 'alert']);
    assert.ok(events[1].args[1] instanceof Error);
  }
});

test('logs the original authentication error to the console while keeping the alert generic', async () => {
  const cause = new Error('Provider failure containing secret-token');

  const events = await loadPage(
    {
      issuer: 'https://id.example.test',
      caSignUrl: 'https://ca.example.test/sign',
      clientId: 'public-client',
      redirectUri,
    },
    200,
    cause,
  );

  const diagnostics = events.filter(event => event.type === 'diagnostic');
  assert.equal(diagnostics.length, 1);
  assert.equal(diagnostics[0].args[1], cause);

  const alerts = events.filter(event => event.type === 'alert');
  assert.equal(alerts.length, 1);
  assert.doesNotMatch(alerts[0].message, /secret-token|Provider failure/);
});
