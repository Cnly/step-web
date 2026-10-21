// The page narrows connections to configured origins after loading config.json.
// HTTP is limited to explicit loopback hosts for local development.
export const csp = "default-src 'none'; script-src 'self'; connect-src 'self' https: http://localhost:* http://127.0.0.1:*; base-uri 'none'; form-action 'none'; object-src 'none'";

export const headers = {
  'Content-Security-Policy': `${csp}; frame-ancestors 'none'`,
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Cache-Control': 'no-store',
};
