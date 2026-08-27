import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { access, chmod, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { inspectGitState } from '../src/git-state.mjs';

test('receiver Git observation ignores replacement refs and detects their substituted worktree bytes', async () => {
  await withRepository(async ({ root, head, tree }) => {
    await writeFile(path.join(root, 'app.txt'), 'replacement bytes\n');
    git(root, ['add', 'app.txt']);
    git(root, ['-c', 'user.name=fixture', '-c', 'user.email=fixture@invalid', 'commit', '--quiet', '-m', 'replacement']);
    const replacement = git(root, ['rev-parse', 'HEAD']).trim();
    git(root, ['reset', '--hard', '--quiet', head]);
    git(root, ['replace', head, replacement]);
    git(root, ['reset', '--hard', '--quiet', head]);
    assert.equal(await readFile(path.join(root, 'app.txt'), 'utf8'), 'replacement bytes\n');
    assert.equal(git(root, ['rev-parse', 'HEAD']).trim(), head);
    assert.notEqual(git(root, ['rev-parse', 'HEAD^{tree}']).trim(), tree);

    const observed = await inspectGitState(root);
    assert.equal(observed.head, head);
    assert.equal(observed.tree, tree);
    assert.equal(observed.workingTreeClean, false);
  });
});

test('receiver Git observation does not trust skip-worktree or assume-unchanged index flags', async () => {
  await withRepository(async ({ root }) => {
    git(root, ['update-index', '--skip-worktree', 'app.txt']);
    await writeFile(path.join(root, 'app.txt'), 'hidden by candidate index\n');
    assert.equal(git(root, ['status', '--porcelain=v1', '--untracked-files=all']), '');
    assert.equal((await inspectGitState(root)).workingTreeClean, false);

    git(root, ['update-index', '--no-skip-worktree', 'app.txt']);
    git(root, ['reset', '--hard', '--quiet', 'HEAD']);
    git(root, ['update-index', '--assume-unchanged', 'app.txt']);
    await writeFile(path.join(root, 'app.txt'), 'hidden by assume-unchanged\n');
    assert.equal(git(root, ['status', '--porcelain=v1', '--untracked-files=all']), '');
    assert.equal((await inspectGitState(root)).workingTreeClean, false);
  });
});

test('receiver Git observation ignores local filemode configuration and compares executable bits itself', async (context) => {
  if (process.platform === 'win32') return context.skip('executable mode is not represented by the Windows worktree');
  await withRepository(async ({ root }) => {
    git(root, ['config', 'core.filemode', 'false']);
    await chmod(path.join(root, 'app.txt'), 0o755);
    assert.equal(git(root, ['status', '--porcelain=v1', '--untracked-files=no']), '');
    assert.equal((await inspectGitState(root)).workingTreeClean, false);
  });
});

test('receiver Git observation hashes raw bytes without executing candidate-configured clean filters', async () => {
  await withRepository(async ({ root }) => {
    await writeFile(path.join(root, '.gitattributes'), 'app.txt filter=mask\n');
    git(root, ['add', '.gitattributes']);
    git(root, ['-c', 'user.name=fixture', '-c', 'user.email=fixture@invalid', 'commit', '--quiet', '-m', 'attributes']);
    const filter = path.join(root, '.git/hostile-filter.sh');
    const marker = path.join(root, '.git/filter-ran');
    await writeFile(filter, `#!/bin/sh\ntouch ${shellQuote(shellPath(marker))}\nsed 's/^changed /canonical /'\n`);
    await chmod(filter, 0o700);
    git(root, ['config', 'filter.mask.clean', `sh ${shellQuote(shellPath(filter))}`]);
    git(root, ['config', 'filter.mask.required', 'true']);
    await writeFile(path.join(root, 'app.txt'), 'changed bytes\n');
    const expectedBlob = git(root, ['ls-tree', 'HEAD', 'app.txt']).trim().split(/\s+/)[2];
    assert.equal(git(root, ['hash-object', '--path=app.txt', 'app.txt']).trim(), expectedBlob);
    await access(marker);
    await rm(marker);

    assert.equal((await inspectGitState(root)).workingTreeClean, false);
    await assert.rejects(access(marker), { code: 'ENOENT' });
  });
});

test('receiver Git observation never lazily fetches missing objects through candidate Git configuration', async () => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'assurance-receiver-promisor-'));
  const source = path.join(fixture, 'source');
  const client = path.join(fixture, 'client');
  const marker = path.join(fixture, 'external-upload-pack-ran');
  const helper = path.join(fixture, 'upload-pack.sh');
  try {
    await mkdir(source);
    await writeFile(path.join(source, 'app.txt'), 'canonical bytes\n');
    git(source, ['init', '--quiet']);
    git(source, ['add', 'app.txt']);
    git(source, ['-c', 'user.name=fixture', '-c', 'user.email=fixture@invalid', 'commit', '--quiet', '-m', 'candidate']);
    const head = git(source, ['rev-parse', 'HEAD']).trim();
    const commit = git(source, ['cat-file', 'commit', head]);

    await mkdir(client);
    git(client, ['init', '--quiet']);
    const written = execFileSync('git', ['-C', client, 'hash-object', '-t', 'commit', '-w', '--stdin'], {
      encoding: 'utf8',
      input: commit,
    }).trim();
    assert.equal(written, head);
    git(client, ['update-ref', 'refs/heads/main', head]);
    git(client, ['symbolic-ref', 'HEAD', 'refs/heads/main']);
    await writeFile(path.join(client, 'app.txt'), 'canonical bytes\n');
    await writeFile(helper, `#!/bin/sh\ntouch ${shellQuote(marker)}\nexec git-upload-pack "$1"\n`);
    await chmod(helper, 0o700);
    git(client, ['config', 'extensions.partialClone', 'origin']);
    git(client, ['config', 'remote.origin.promisor', 'true']);
    git(client, ['config', 'remote.origin.partialclonefilter', 'blob:none']);
    git(client, ['config', 'remote.origin.url', source]);
    git(client, ['config', 'remote.origin.uploadpack', helper]);

    await assert.rejects(inspectGitState(client), /missing|bad object|not a tree|unable to read tree|invalid object|needed a single revision/i);
    await assert.rejects(access(marker), { code: 'ENOENT' });
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});

test('receiver Git observation rejects tracked paths whose directory ancestor is replaced by a symlink', async () => {
  const outside = await mkdtemp(path.join(os.tmpdir(), 'assurance-receiver-outside-'));
  try {
    await withRepository(async ({ root }) => {
      const trackedDirectory = path.join(root, 'dir');
      await mkdir(trackedDirectory);
      await writeFile(path.join(trackedDirectory, 'app.txt'), 'same bytes\n');
      git(root, ['add', 'dir/app.txt']);
      git(root, ['-c', 'user.name=fixture', '-c', 'user.email=fixture@invalid', 'commit', '--quiet', '-m', 'nested candidate']);
      await writeFile(path.join(outside, 'app.txt'), 'same bytes\n');
      await rm(trackedDirectory, { recursive: true });
      await symlink(outside, trackedDirectory, 'dir');

      const observed = await inspectGitState(root);
      assert.equal(observed.workingTreeClean, false);
    });
  } finally {
    await rm(outside, { recursive: true, force: true });
  }
});

test('receiver Git observation rejects tree names that become separators on another supported host', {
  skip: process.platform === 'win32' && 'Windows cannot create a Git worktree entry containing a backslash',
}, async () => {
  await withRepository(async ({ root }) => {
    await writeFile(path.join(root, '..\\outside'), 'portable boundary\n');
    git(root, ['add', '--', '..\\outside']);
    git(root, ['-c', 'user.name=fixture', '-c', 'user.email=fixture@invalid', 'commit', '--quiet', '-m', 'nonportable tree path']);
    await assert.rejects(inspectGitState(root), /unsafe path/);
    assert.equal(path.win32.resolve('C:\\candidate', '..\\outside'), 'C:\\outside');
  });
});

test('shadow Git observation rejects non-ignored untracked files and deliberately ignores ignored files', async () => {
  await withRepository(async ({ root }) => {
    await writeFile(path.join(root, 'telemetry.json'), '{}\n');
    assert.equal((await inspectGitState(root, { includeUntracked: false })).workingTreeClean, true);
    assert.equal((await inspectGitState(root, { includeUntracked: true })).workingTreeClean, false);
    await rm(path.join(root, 'telemetry.json'));

    await writeFile(path.join(root, '.gitignore'), 'ignored.log\n');
    git(root, ['add', '.gitignore']);
    git(root, ['-c', 'user.name=fixture', '-c', 'user.email=fixture@invalid', 'commit', '--quiet', '-m', 'ignore rule']);
    await writeFile(path.join(root, 'ignored.log'), 'ignored producer output\n');
    assert.equal((await inspectGitState(root, { includeUntracked: true })).workingTreeClean, true);
  });
});

async function withRepository(callback) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'assurance-receiver-git-'));
  try {
    await mkdir(root, { recursive: true });
    await writeFile(path.join(root, 'app.txt'), 'canonical bytes\n');
    git(root, ['init', '--quiet']);
    git(root, ['config', 'core.autocrlf', 'false']);
    git(root, ['add', 'app.txt']);
    git(root, ['-c', 'user.name=fixture', '-c', 'user.email=fixture@invalid', 'commit', '--quiet', '-m', 'candidate']);
    const head = git(root, ['rev-parse', 'HEAD']).trim();
    const tree = git(root, ['rev-parse', 'HEAD^{tree}']).trim();
    await callback({ root, head, tree });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

function git(root, args) {
  return execFileSync('git', ['-C', root, ...args], { encoding: 'utf8' });
}

function shellQuote(value) {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function shellPath(value) {
  return process.platform === 'win32' ? value.replaceAll('\\', '/') : value;
}
