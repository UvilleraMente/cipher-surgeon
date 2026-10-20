// Bundles the framework-free core and the CLI into a single Node.js script.
import { build } from 'esbuild';

await build({
  entryPoints: ['cli/cipher-surgeon.ts'],
  outfile: 'cli/dist/cipher-surgeon.mjs',
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node20',
  banner: { js: '#!/usr/bin/env node' },
  logLevel: 'info',
});
