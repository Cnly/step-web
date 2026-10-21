import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';

test('build emits nginx directives and config-independent assets, preserving runtime configuration', async () => {
  const temporary = await mkdtemp(join(tmpdir(), 'step-web-build-'));
  const directory = join(temporary, 'dist');
  const configPath = join(directory, 'config.json');
  const build = () => execFileSync(
    process.execPath,
    ['scripts/build.js', directory],
    { cwd: new URL('../', import.meta.url), stdio: 'pipe' },
  );

  try {
    build();

    await assert.rejects(readFile(configPath), { code: 'ENOENT' });

    const html = await readFile(join(directory, 'index.html'), 'utf8');
    const bundle = await readFile(join(directory, 'app.js'));
    const nginx = await readFile(join(directory, 'nginx.conf'), 'utf8');
    const headers = Object.fromEntries(
      nginx.trimEnd().split('\n').map(line => {
        const directive = /^add_header ([\w-]+) "([^"]*)" always;$/.exec(line);

        assert.ok(directive, `Invalid nginx header directive: ${line}`);

        return directive.slice(1);
      }),
    );

    assert.ok(
      html.includes(`integrity="sha384-${createHash('sha384').update(bundle).digest('base64')}"`),
    );
    assert.ok(html.includes('src="./app.js"'));
    assert.equal(
      await readFile(join(directory, 'LICENSE'), 'utf8'),
      await readFile(new URL('../LICENSE', import.meta.url), 'utf8'),
    );

    const notices = await readFile(join(directory, 'THIRD-PARTY-LICENSES.txt'), 'utf8');
    const lock = JSON.parse(await readFile(new URL('../package-lock.json', import.meta.url), 'utf8'));
    for (const [path, entry] of Object.entries(lock.packages)) {
      if (!path || entry.dev) continue;
      const name = path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length);
      assert.ok(notices.includes(`${name} ${entry.version}\n`), `Missing license for ${name}`);
    }

    assert.match(headers['Content-Security-Policy'], /script-src 'self'/);
    assert.equal(
      headers['Content-Security-Policy'].split('; ').find(directive => directive.startsWith('connect-src ')),
      "connect-src 'self' https: http://localhost:* http://127.0.0.1:*",
    );
    assert.match(headers['Content-Security-Policy'], /frame-ancestors 'none'/);
    assert.ok(!headers['Content-Security-Policy'].includes('unsafe-'));

    assert.equal(headers['Referrer-Policy'], 'no-referrer');
    assert.equal(headers['X-Content-Type-Options'], 'nosniff');
    assert.equal(headers['X-Frame-Options'], 'DENY');
    assert.equal(headers['Cache-Control'], 'no-store');

    // Building must neither read nor overwrite an operator-managed config.
    const runtimeConfig = '{ "managed": "at runtime" }\n';
    await writeFile(configPath, runtimeConfig);

    build();

    assert.equal(await readFile(configPath, 'utf8'), runtimeConfig);
    assert.deepEqual(await readFile(join(directory, 'app.js')), bundle);
    assert.equal(await readFile(join(directory, 'index.html'), 'utf8'), html);
    assert.equal(await readFile(join(directory, 'nginx.conf'), 'utf8'), nginx);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});
