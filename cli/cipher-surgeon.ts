import { readFileSync } from 'node:fs';
import { run } from './main';

process.exitCode = await run(process.argv.slice(2), {
  readFile: (path) => readFileSync(path, 'utf8'),
  readStdin: () => readFileSync(0, 'utf8'),
  stdout: (text) => process.stdout.write(text),
  stderr: (text) => process.stderr.write(text),
  env: (name) => process.env[name],
  now: () => Math.floor(Date.now() / 1000),
});
