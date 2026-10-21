import { OidcClient, WebStorageStateStore } from 'oidc-client-ts';

const PREFIX = 'step-web.oidc.';
const STATE_MAX_AGE_SECONDS = 10 * 60;
const CALLBACK_FIELDS = new Set([
  'code', 'state', 'error', 'error_description', 'error_uri', 'session_state', 'iss',
  'id_token', 'access_token', 'token_type',
]);

/** A callback is never retried automatically, including an OAuth error callback. */
function hasCallback(url) {
  return [...url.searchParams.keys()].some(key => CALLBACK_FIELDS.has(key)) ||
    /(?:^|[&#])(?:code|state|error|id_token|access_token)=/.test(url.hash);
}

function browserEnvironment() {
  return {
    url: window.location.href,
    storage: window.sessionStorage,
    navigate: href => window.location.assign(href),
    replaceUrl: href => window.history.replaceState(null, '', href),
  };
}

function clearOwnState(storage) {
  for (let i = storage.length - 1; i >= 0; i--) {
    const key = storage.key(i);
    if (key?.startsWith(PREFIX)) storage.removeItem(key);
  }
}

/** Returns null after starting navigation, otherwise the identity from the OIDC response. */
export async function authenticate(config, environment = browserEnvironment()) {
  const { url: input, storage, navigate, replaceUrl } = environment;
  const current = new URL(input);
  const redirect = new URL(config.redirectUri);
  const callback = hasCallback(current);

  const stateStore = new WebStorageStateStore({ prefix: PREFIX, store: storage });
  const client = new OidcClient({
    authority: config.issuer,
    client_id: config.clientId,
    client_secret: config.clientSecret,
    redirect_uri: config.redirectUri,
    scope: config.scope ?? 'openid email',
    stateStore,
    staleStateAgeInSeconds: STATE_MAX_AGE_SECONDS,
    requestTimeoutInSeconds: 15,
  });

  if (!callback) {
    clearOwnState(storage);
    const nonce = crypto.randomUUID();
    const request = await client.createSigninRequest({ nonce });

    navigate(request.url);
    return null;
  }

  replaceUrl(redirect.href); // Remove the code before any network request.

  // Expire old transactions before the library looks up the callback state.
  await client.clearStaleState();

  const response = await client.processSigninResponse(current.href);
  const claims = response.profile;

  return {
    idToken: response.id_token,
    subject: claims.sub,
    ...(typeof claims.email === 'string' ? { email: claims.email } : {}),
  };
}
