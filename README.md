# step-web

A static, dialog-only step-ca enrollment page. A fresh visit loads the runtime
configuration and redirects to OIDC login. After the callback, a native prompt
displays an editable generated password. OK creates a P-256 key in the browser,
submits a CSR to step-ca, and downloads
`<portal-hostname>-YYYY-MM-DD.p12`, using the device's local date at download time.
Cancel stops before key generation or certificate issuance.

Key generation and PKCS#12 export run in the browser. The signing request contains
only the CSR, ID token, and requested certificate lifetime. The portal is static;
it requires an existing OIDC provider and step-ca deployment. It has no UI
framework, CDN script, service worker, analytics, or persistent token store.

## Configure and build

Use Node.js 22+ and npm. OpenSSL 3 or newer is needed for the interoperability
tests. If the default executable is older or LibreSSL, set `OPENSSL` when running
tests, for example `OPENSSL=/opt/homebrew/bin/openssl npm test`.

From the repository root:

```sh
npm ci --ignore-scripts
npm test
npm run build
cp config.example.json config.local.json
# Edit config.local.json, especially redirectUri, then:
cp config.local.json dist/config.json
```

Keep deployment settings in the ignored `config.local.json`; commit only the
placeholder `config.example.json`. Runtime configs, environment files, generated
certificate bundles, and private keys are ignored to reduce accidental commits.
Review the files being staged before publishing; ignore rules do not protect files
that were already tracked or explicitly force-added.

Serve **only the build output directory** (`dist/` by default), over publicly
trusted HTTPS. The build emits static assets without reading or writing
configuration. The page fetches `./config.json` on each visit and then starts
authentication. This file must contain only public settings. Changing it takes
effect on the next page load; no rebuild is needed. Configuration is trusted
deployment input, with no separate schema validator. The page requires a browser
secure context and uses the configured origins to set its CSP connection policy.

The example contains placeholder settings. Set your issuer, client ID,
portal URL, and CA endpoint, and register the portal's redirect URI with your IdP.
Tests use independent fixtures; editing the example does not change their inputs.

### Nix

The flake uses `nixpkgs` from `nixos-26.05` and the `systems` registry input.
`flake.lock` pins both inputs. With Nix's `nix-command` and `flakes` features
enabled, run these commands from the repository root:

```sh
nix build                     # Default package; static files in ./result
nix build .#step-web           # The same package by name
nix build '.#step-web^nginx' --out-link result-nginx
nix flake check                # Builds the package and runs its Node/OpenSSL tests
nix develop                    # Shell with Node.js 24, npm, and OpenSSL
```

The development shell sets `OPENSSL` to its packaged executable.
Run `npm ci --ignore-scripts` before using the npm commands in that shell.
The Apple import probe still needs macOS 15+ and Swift from the host.

Packages, checks, and development shells are exposed for each system from the
`systems` input. In a Git checkout, Nix only includes files known to Git; add new
source files and keep `flake.lock` under version control. `default.nix` remains
usable with `pkgs.callPackage /path/to/step-web { }` in an existing package set.

The Nix package has two outputs: `step-web.out` (the default) contains the static
web files, and `step-web.nginx` contains `nginx.conf`, an include snippet with
`add_header ... always;` directives for an nginx location.
Serve an operator-managed file at `/config.json` using your web server,
or place the package assets in a writable runtime web root and copy, symlink, or
bind-mount the config there. For a page hosted under a URL prefix, serve the
config under that same prefix. Do not try to write into the immutable Nix store.
For example, use this expression for a NixOS nginx virtual host's configuration,
replacing `/path/to/step-web` with the repository path and configuring HTTPS on
the virtual host:

```nix
let
  stepWeb = pkgs.callPackage /path/to/step-web { };
in {
  locations."/" = {
    root = "${stepWeb}";
    extraConfig = ''
      include ${stepWeb.nginx}/nginx.conf;
    '';
  };
  locations."= /config.json" = {
    alias = "/run/step-web/config.json";
    extraConfig = ''
      default_type application/json;
      include ${stepWeb.nginx}/nginx.conf;
    '';
  };
}
```

Include the snippet in every location serving portal files, including the runtime
config. nginx normally stops inheriting parent `add_header` directives when a
location defines its own, so include any deployment headers such as HSTS there
as well. For a dedicated virtual host, you can instead include the snippet at
server level and inherit it in locations without their own `add_header` directives.

For a plain npm build, the same snippet is emitted as `dist/nginx.conf`.
Rebuilding preserves runtime `config.json`. The build command accepts an optional
output directory: `npm run build -- /path/to/web-root`. `npm run serve` always
serves `dist/`; use another server for a custom output directory. nginx requires
an explicit `include` of the snippet; placing it in the web root does not apply it.

### Runtime configuration

| Setting | Meaning |
| --- | --- |
| `issuer` | Exact OIDC discovery issuer URL. Use HTTPS in production; HTTP loopback can be used for local preview. |
| `clientId` | OIDC client ID, also accepted by step-ca's OIDC provisioner. |
| `clientSecret` | Optional provider-required value sent using `client_secret_post`. Visible to anyone who can load the portal; omitted or empty means no secret is sent. |
| `redirectUri` | Exact registered URL of this page, including path/trailing slash. Used for the OIDC redirect and to clear callback parameters. Use HTTPS, or HTTP loopback for local preview. |
| `caSignUrl` | Signing endpoint, normally `https://your-ca/1.0/sign`. HTTP loopback is supported for local preview. |
| `scope` | OIDC scope string; defaults to `openid email`. Include `openid` to request an ID token. |
| `certificateDuration` | Requested lifetime sent to step-ca as `notAfter`; defaults to `24h`. The CA validates it and enforces its own limit. |
| `oidcExtraOrigins` | Additional origins allowed by CSP for OIDC network requests, such as a token endpoint outside the issuer's origin. URL entries are reduced to their origins, including scheme and port. Defaults to `[]`. |

Some providers require a client secret even for browser applications. Set
`clientSecret` for compatibility with such a provider's `client_secret_post`
token authentication. It is sent in the token request's form body, never the
authorization URL. It is public in `config.json`, and the OIDC library also keeps
it in temporary sessionStorage transaction state. This does not make the portal
a confidential client or replace PKCE. If the provider requires the secret to
remain confidential, the token exchange needs a server-side component.

The CSR common name and PKCS#12 friendly name use the ID token's nonempty email,
falling back to `sub`. The CA controls the issued certificate's subject and SANs.
Tokens and all requested certificate fields must be authorized by the CA
independently of this untrusted browser client.

## IdP and CA prerequisites

- Register `redirectUri` for an OIDC client supporting browser authorization code
  flow and PKCE S256. Use token endpoint authentication `none` where supported,
  or configure `clientSecret` for `client_secret_post`. Discovery and token
  responses must allow the portal origin through CORS. The IdP must return the
  requested nonce in the ID token.
- Configure step-ca's OIDC provisioner to accept the same issuer and client ID.
  It receives the **ID token** as `ott`, not the access token. step-ca validates
  the token signature and enforces who may enroll, subject/SANs, key usage, and
  lifetime. Configure an issuance template with the key usages and SANs required
  by your application. The exporter checks that the leaf certificate matches the
  generated public key; certificate usage policy is left to the CA and the
  applications using the certificate.
  The signing response must contain PEM certificates in a leaf-first `certChain`
  array, or `crt` with an optional `ca` certificate.
- Expose the CA endpoint through publicly trusted HTTPS (for example, Let's
  Encrypt), with CORS for the portal's exact origin, `POST` and `Content-Type`.
  Alternatively, reverse-proxy `/1.0/sign` on the portal origin to step-ca, set
  `caSignUrl` to that public URL, and verify the upstream CA's TLS certificate.
  Do not expose administrative endpoints or log signing request bodies.
- Include the generated `nginx.conf` in the nginx locations serving the portal
  and runtime configuration. The HTML also includes a CSP fallback, but framing
  protection requires HTTP headers. Do not inject scripts or enable HTML
  rewriting that changes the bundle/SRI relationship.

The initial CSP allows connections to HTTPS, the page's own origin, and HTTP
`localhost`/`127.0.0.1` for development. Immediately after loading the runtime
config, the page adds a policy restricting connections to the configured issuer,
CA, extra OIDC origins, and its own origin, before making authentication requests.
The authorization redirect uses the endpoint returned by OIDC discovery.
These connection restrictions begin after config loads; the local-script and other
restrictions apply from the initial HTML. To restrict connections from the start
as well, set a stricter deployment-specific HTTP CSP in your web server. Multiple
policies are enforced together, so an existing stricter server policy must also
allow your configured endpoints.

This page explicitly requests 24 hours unless configured otherwise; the CA
enforces its own lifetime policy. There is no renewal agent: reload and
authenticate again to create a new key/certificate, then import it again.

For local preview, register a loopback redirect URI, set it to exactly
`http://127.0.0.1:8080/` in `dist/config.json`, then run `npm run serve`.
Copy or symlink your local configuration to `dist/config.json` first; the server
exits immediately if that file is missing or unreadable. JSON parsing happens in
the browser. To use another port, run `npm run serve -- 8081` and update the
registered redirect URI and config to match. The server binds to `127.0.0.1` and
applies the same headers as the nginx snippet.

`npm test` and `npm run test:apple` use fixtures and need neither a local config
file nor a running IdP or CA. For local HTTP IdP or CA endpoints, use `localhost`
or `127.0.0.1`, which the initial CSP allows; browser mixed-content restrictions
still apply. For IPv6 loopback, use a same-origin reverse proxy. `serve` is a
loopback development server, not a production HTTPS server.

## Apple compatibility

The bundle uses PBES2 AES-256-CBC with PBKDF2-HMAC-SHA256 for key and certificate
encryption, and conventional PKCS#12 HMAC-SHA256 integrity. Both KDF iteration
counts are 100,000. It contains the leaf and returned chain, with matching
`localKeyId` attributes for the leaf and private key. SHA-1 is used only to
derive this public linking identifier, not for encryption, signatures, or MAC.

The default password has 16 random letters and digits (about 95 bits of
randomness). The page tries to copy it to the clipboard before showing the
prompt and tells you whether it succeeded. Safari generally blocks this
automatic copy because it requires a page click; copy the password manually
when prompted. You may replace it with any password, including an empty one.
If you edit it, copy the new value yourself before continuing.

The Apple probe covers nonempty ASCII and Unicode passwords. Empty passwords are
covered by the OpenSSL tests only; use a nonempty password for Apple imports.

The browser bundle targets Safari 18 syntax. Native import of the chosen PKCS#12
algorithms requires macOS 15+ or iOS/iPadOS 18+; see Apple's notes on
[algorithm support](https://developer.apple.com/forums/thread/770012) and
[macOS import APIs](https://developer.apple.com/forums/thread/779466).
On macOS, open the downloaded `.p12` in Keychain Access and import into the login
keychain. On iPhone/iPad, use Safari and finish the certificate installation in
Settings. Other iOS browsers do not necessarily have access to
[identities installed for Safari](https://developer.apple.com/forums/thread/757401).
The portal does not emit `.mobileconfig` or manage devices.

```sh
npm run test:apple
```

On macOS 15+ with Swift and OpenSSL available, this generates a disposable
certificate bundle with the actual exporter, imports it with ASCII and Unicode
passwords using `kSecImportToMemoryOnly`, and signs/verifies a message. It does not
modify the keychain or trust store. This probe runs separately from `npm test` and is
skipped on non-macOS systems. The Node tests verify the CSR and PKCS#12 using
OpenSSL, including certificate and key recovery with Unicode and empty passwords,
and wrong-password failure. Both test commands honor `OPENSSL`.

**Deployment verification:** test the browser-generated Blob download,
installation, and intended certificate use on your target devices. For Safari
mTLS, test on a physical current iPhone/iPad.
The memory-only API test does not establish that download/install handoff. Also
test real OIDC login and CA issuance after registering the portal URL. Do not
enable broad root trust just to import a certificate; for mTLS, the server must
trust its issuing CA, separately from the browser trusting the server's HTTPS
certificate.

## Dependencies and security boundaries

Runtime dependencies are `oidc-client-ts` (OIDC protocol), `pkijs` (CSR and
PKCS#12), and `asn1js` (ASN.1 structures). esbuild is the sole build dependency.
Direct versions are exact; `package-lock.json` pins transitive versions and
registry integrity hashes. `.npmrc` disables lifecycle scripts. esbuild uses
its locked platform binary without running its install hook; do not omit npm's
optional dependencies. Tests use Node's built-in test runner, not another npm
test framework. Runtime package licenses ship in `THIRD-PARTY-LICENSES.txt`.

The lockfile pins PKI.js 3.4.1 and its `@noble/hashes` 1.8.0 dependency, used for
the PKCS#12 MAC KDF. Not every cryptographic operation is native WebCrypto.

Run dependency checks separately when reviewing a build or dependency update;
they are not part of the build or test scripts, and automatic install-time
auditing is disabled in `.npmrc`:

```sh
npm audit
npm audit signatures
```

These checks report known advisories and verify available registry signatures
and provenance attestations; they do not prove publisher code is safe. Review
dependency updates and lockfile changes before running a new build. Do not run
`npm audit fix --force`, use floating/CDN imports, or switch to an unreviewed
export helper.

OIDC transactions use sessionStorage with a ten-minute maximum age and a fresh
nonce. Callback codes are removed from the URL. The OIDC library handles state
consumption, PKCE and nonce validation, and supplies the decoded identity claims.
The app does not duplicate those checks or validate ID-token signatures, issuer,
audience, or expiry; **step-ca validates the token and authorizes issuance before
signing**. The page's CSP restricts connections to configured origins.
The app does not persist access/ID tokens or keys, fetch userinfo, or silently renew.

Failures are logged once to the browser console with their original error causes;
alerts show brief messages. Console diagnostics may contain sensitive provider
details, so redact them before sharing. The app adds no remote logging service.

PKCS#12 export requires an extractable private key. It is not Secure Enclave
bound. A compromised portal origin or malicious build can steal that key and
password despite encryption of the downloaded file. Use a dedicated origin,
restrict who can change the deployed files, and avoid third-party scripts.
JavaScript also cannot guarantee erasure of all memory copies. Keep the
downloaded certificate bundle and password private and remove unwanted duplicate
imports.

## License

[MIT](LICENSE). Builds include this license and `THIRD-PARTY-LICENSES.txt` for
runtime dependencies; retain both when redistributing the static files.
`"private": true` in `package.json` prevents accidental npm publication and does
not restrict publishing this repository.
