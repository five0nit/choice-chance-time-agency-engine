import { build } from 'esbuild';
import { cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const source = join(root, 'src');
const dist = join(root, 'dist');

await rm(dist, { recursive: true, force: true });
await mkdir(join(dist, 'assets'), { recursive: true });

const result = await build({
  entryPoints: [join(source, 'app.js')],
  bundle: true,
  format: 'esm',
  platform: 'browser',
  target: ['es2022'],
  outdir: join(dist, 'assets'),
  entryNames: 'app-[hash]',
  assetNames: 'asset-[hash]',
  minify: true,
  metafile: true,
  sourcemap: false,
  legalComments: 'none',
});

const outputs = Object.keys(result.metafile.outputs);
const script = outputs.find((path) => path.endsWith('.js'));
const stylesheet = outputs.find((path) => path.endsWith('.css'));
if (!script || !stylesheet) throw new Error('expected hashed JavaScript and CSS outputs');

let html = await readFile(join(root, 'index.template.html'), 'utf8');
html = html
  .replace('__APP_SCRIPT__', `/${relative(dist, script).replaceAll('\\\\', '/')}`)
  .replace('__APP_STYLES__', `/${relative(dist, stylesheet).replaceAll('\\\\', '/')}`);
if (html.includes('__APP_')) throw new Error('unresolved hosting template marker');
await writeFile(join(dist, 'index.html'), html, { encoding: 'utf8', mode: 0o644 });
await cp(join(source, 'firebase-config.js'), join(dist, 'firebase-config.js'));
console.log(`BUILD_OK script=${relative(dist, script)} css=${relative(dist, stylesheet)}`);
