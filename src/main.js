import { authenticate } from './auth.js';
import { enroll, EnrollmentError } from './enroll.js';

let phase = 'Loading configuration';

try {
  if (!window.isSecureContext || !crypto.subtle) throw new Error('Secure context required');

  const response = await fetch('./config.json', {
    cache: 'no-store',
    credentials: 'omit',
    redirect: 'error',
  });
  if (!response.ok) throw new Error('Configuration unavailable');

  const config = await response.json();

  const origins = new Set([
    config.issuer,
    config.caSignUrl,
    ...(config.oidcExtraOrigins ?? []),
  ].map(url => new URL(url).origin));
  const policy = document.createElement('meta');
  policy.httpEquiv = 'Content-Security-Policy';
  policy.content = `connect-src 'self' ${[...origins].join(' ')}`;
  document.head.append(policy);

  phase = 'Authentication';
  const session = await authenticate(config);

  if (session) {
    phase = 'Certificate issuance';
    try {
      if (await enroll(config, session)) {
        alert(
          'Your certificate has been created! Check your Download folder. ' +
          'Open it and enter your password to import your certificate.\n\n' +
          "Some apps may ask for it separately even if you've imported it into the OS.\n\n" +
          'You can now close this page.'
        );
      } else {
        alert('Cancelled. No certificate was requested. Reload this page to start again.');
      }
    } finally {
      session.idToken = '';
    }
  }
} catch (error) {
  // Keep raw diagnostics in DevTools; they may contain sensitive provider details.
  console.error(`[step-web] ${phase} failed`, error);

  alert(
    error instanceof EnrollmentError
      ? error.message
      : `${phase} failed. ` +
        'Check the deployment configuration and network access, then reload to start again. ' +
        'No automatic retry will occur.'
  );
}
