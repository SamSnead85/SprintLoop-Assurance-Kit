import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';

const result = spawnSync('npm', ['pack', '--dry-run'], {
  cwd: process.cwd(),
  encoding: 'utf8',
  env: {
    ...process.env,
    npm_config_cache: path.join(os.tmpdir(), 'sprintloop-assurance-kit-npm-cache'),
  },
});
process.stdout.write(result.stdout ?? '');
process.stderr.write(result.stderr ?? '');
process.exitCode = result.status ?? 1;
