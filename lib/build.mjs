// Bundles the public library entry (lib/index.ts) as ESM and CommonJS.
// Type declarations are emitted separately by `tsc -p tsconfig.lib.json`.
import { rmSync } from 'node:fs';
import { build } from 'esbuild';

rmSync('lib/dist', { recursive: true, force: true });

const common = {
  entryPoints: ['lib/index.ts'],
  bundle: true,
  platform: 'neutral',
  target: 'es2020',
  logLevel: 'info',
};

await Promise.all([
  build({ ...common, format: 'esm', outfile: 'lib/dist/index.mjs' }),
  build({ ...common, format: 'cjs', outfile: 'lib/dist/index.cjs' }),
]);
