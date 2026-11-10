import { createIdentity, createPkcs12 } from './identity.js';

export class EnrollmentError extends Error {}

function generatePassword() {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let password = '';

  while (password.length < 16) {
    for (const byte of crypto.getRandomValues(new Uint8Array(16))) {
      // Reject the last eight values so every character is equally likely.
      if (byte < 248) password += alphabet[byte % alphabet.length];
      if (password.length === 16) return password;
    }
  }
}

function downloadIdentity(bytes, filename) {
  const objectUrl = URL.createObjectURL(
    new Blob([bytes], { type: 'application/x-pkcs12' })
  );
  const anchor = document.createElement('a');
  anchor.href = objectUrl;
  anchor.download = filename;

  document.body.append(anchor);
  anchor.click();
  anchor.remove();

  // Leave time for Safari to consume the Blob after the native dialog closes.
  setTimeout(() => URL.revokeObjectURL(objectUrl), 60_000);
}

export async function enroll(config, session, dependencies = {}) {
  const deps = {
    copy: password => navigator.clipboard.writeText(password),
    prompt: (...args) => window.prompt(...args),
    now: () => new Date(),
    fetch: (...args) => fetch(...args),
    download: downloadIdentity,
    createIdentity,
    createPkcs12,
    ...dependencies,
  };

  const generatedPassword = generatePassword();
  let copied = false;
  try {
    await deps.copy(generatedPassword);
    copied = true;
  } catch {
    // Some browsers require a page click before allowing clipboard writes.
  }

  const password = deps.prompt(
    (copied
      ? 'Your certificate password has been copied to your clipboard. '
      : 'Copy this password for your certificate! ') +
    "You'll need it to import your certificate in a minute, then you can delete them.",
    generatedPassword
  );
  if (password === null) return false;
  if (password !== generatedPassword)
    throw new EnrollmentError(
      'The generated password cannot be changed. Reload this page to start again.'
    );

  const name = session.email || session.subject;
  if (!session.idToken || typeof name !== 'string' || !name || name.length > 256)
    throw new EnrollmentError('The identity provider did not return a usable identity.');

  const identity = await deps.createIdentity(name);

  let response;
  try {
    response = await deps.fetch(config.caSignUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({
        csr: identity.csrPem,
        ott: session.idToken,
        notAfter: config.certificateDuration ?? '24h',
      }),
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
      signal: AbortSignal.timeout(30_000),
    });
  } catch (error) {
    throw new EnrollmentError(
      'Could not contact step-ca. ' +
      'Check HTTPS, CORS, and the configured signing URL. Reload to authenticate again.',
      { cause: error }
    );
  }

  // Do not display the response body: it can contain the submitted token.
  if (!response.ok)
    throw new EnrollmentError(
      `step-ca rejected the request (HTTP ${response.status}). ` +
      `Check its OIDC provisioner and issuance policy, then reload to authenticate again.`
    );

  let result;
  try {
    const body = await response.text();
    if (body.length > 1_048_576) throw new Error('response too large');
    result = JSON.parse(body);
  } catch (error) {
    throw new EnrollmentError('step-ca returned an invalid signing response.', { cause: error });
  }

  const chain = result?.certChain ?? [result?.crt, result?.ca].filter(Boolean);
  if (
    !Array.isArray(chain) || !chain.length || chain.length > 8 ||
    chain.some(pem => typeof pem !== 'string' || !pem)
  ) {
    throw new EnrollmentError('step-ca did not return a usable certificate chain.');
  }

  let bytes;
  try {
    bytes = await deps.createPkcs12({
      privateKey: identity.privateKey,
      publicKey: identity.publicKey,
      certificateChainPem: chain,
      password,
      friendlyName: name,
    });
  } catch (error) {
    throw new EnrollmentError(
      'PKCS#12 export failed. Check the browser console for details before retrying.',
      { cause: error }
    );
  }

  const now = deps.now();
  const date = [
    now.getFullYear(),
    String(now.getMonth() + 1).padStart(2, '0'),
    String(now.getDate()).padStart(2, '0'),
  ].join('-');
  const filename = `${new URL(config.redirectUri).hostname}-${date}.p12`;
  deps.download(bytes, filename);

  return true;
}
