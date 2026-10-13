import { copyFile, mkdir, rm } from 'node:fs/promises';
import { build } from 'esbuild';

await rm('public', { recursive: true, force: true });
await mkdir('public/assets', { recursive: true });
await Promise.all(['index.html', 'login.html', 'register.html'].map(page => copyFile(page, `public/${page}`)));
await build({
  entryPoints: ['src/auth.js'],
  outfile: 'public/assets/auth.js',
  bundle: true,
  minify: true,
  platform: 'browser',
  target: 'es2022',
});
