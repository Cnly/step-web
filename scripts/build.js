import { build } from 'esbuild';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { csp, headers } from './headers.js';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const output = resolve(process.argv[2] ?? join(root, 'dist'));

if (process.argv.length > 3) {
  console.error(
    'Usage: node scripts/build.js [output-directory]. Serve config.json separately at runtime.',
  );
  process.exit(1);
}

const lock = JSON.parse(await readFile(join(root, 'package-lock.json'), 'utf8'));
const runtimePackages = Object.entries(lock.packages).filter(([path, entry]) => path && !entry.dev);

const alias = {};
const notices = [];

for (const [path] of runtimePackages) {
  const packageRoot = join(root, path);
  const metadata = JSON.parse(await readFile(join(packageRoot, 'package.json'), 'utf8'));

  // Resolve only our locked installation, even inside an unrelated Yarn PnP
  // workspace. Preserve oidc-client-ts's ESM export when using an absolute alias.
  alias[metadata.name] = metadata.name === 'oidc-client-ts'
    ? join(packageRoot, metadata.exports['.'].import)
    : packageRoot;

  // Preserve the licenses for every runtime package, including transitive ones.
  let license;

  for (const filename of ['LICENSE', 'LICENSE.txt', 'LICENSE.md', 'LICENSE-MIT', 'License.txt']) {
    try {
      license = await readFile(join(packageRoot, filename), 'utf8');
      break;
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }

  if (!license) throw new Error(`License file missing for ${metadata.name}.`);

  notices.push(`${metadata.name} ${metadata.version}\n${license}`);
}

await mkdir(output, { recursive: true });

const result = await build({
  absWorkingDir: root,
  entryPoints: ['src/main.js'],
  outfile: join(output, 'app.js'),
  bundle: true,
  format: 'esm',
  platform: 'browser',
  target: ['safari18'],
  alias,
  minify: true,
  sourcemap: false,
  legalComments: 'external',
  write: false,
});

for (const file of result.outputFiles)
  await writeFile(file.path, file.contents);

const bundle = result.outputFiles.find(file => file.path === join(output, 'app.js'));
const integrity = `sha384-${createHash('sha384').update(bundle.contents).digest('base64')}`;

const htmlEscape = value => value
  .replaceAll('&', '&amp;')
  .replaceAll('"', '&quot;')
  .replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;');

const html = `
  <!doctype html>
  <html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="referrer" content="no-referrer">
    <meta http-equiv="Content-Security-Policy" content="${htmlEscape(csp)}">
    <title>Certificate enrollment</title>
    <script type="module" src="./app.js" integrity="${integrity}"></script>
  </head>
  <body><noscript>JavaScript is required to enroll a certificate.</noscript></body>
  </html>
`;

await writeFile(join(output, 'index.html'), html);
await writeFile(
  join(output, 'nginx.conf'),
  Object.entries(headers)
    .map(([key, value]) => `add_header ${key} "${value}" always;\n`)
    .join(''),
);

await writeFile(join(output, 'THIRD-PARTY-LICENSES.txt'), notices.join('\n\n'));
await writeFile(join(output, 'LICENSE'), await readFile(join(root, 'LICENSE')));

console.log(
  `Built ${output} (${Math.ceil(bundle.contents.length / 1024)} KiB JavaScript). Serve this directory over HTTPS with a runtime config.json and include nginx.conf in the serving locations.`,
);
