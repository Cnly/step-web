import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { headers } from './headers.js';

// Loopback preview only. Deploy dist/ using a real HTTPS static server.
const directory = join(dirname(dirname(fileURLToPath(import.meta.url))), 'dist');

try {
  await readFile(join(directory, 'config.json'));
} catch {
  console.error(
    'Cannot read dist/config.json. Copy or symlink your local configuration there before running npm run serve.',
  );
  process.exit(1);
}

const types = {
  'index.html': 'text/html; charset=utf-8',
  'app.js': 'text/javascript; charset=utf-8',
  'config.json': 'application/json',
  'LICENSE': 'text/plain; charset=utf-8',
  'THIRD-PARTY-LICENSES.txt': 'text/plain; charset=utf-8',
  'app.js.LEGAL.txt': 'text/plain; charset=utf-8',
};

const port = Number(process.argv[2] ?? 8080);

createServer(async (request, response) => {
  try {
    const path = new URL(request.url, 'http://localhost').pathname;
    const file = path === '/' ? 'index.html' : path.slice(1);

    if (!Object.hasOwn(types, file) || !['GET', 'HEAD'].includes(request.method)) {
      response.writeHead(404, headers).end();
      return;
    }

    const content = await readFile(join(directory, file));

    response.writeHead(200, { ...headers, 'Content-Type': types[file] });
    response.end(request.method === 'HEAD' ? undefined : content);
  } catch {
    response.writeHead(500, headers).end();
  }
}).listen(
  port,
  '127.0.0.1',
  () => console.log(`Preview: http://127.0.0.1:${port}/ (must match redirectUri to sign in)`),
);
