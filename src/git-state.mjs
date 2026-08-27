import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { constants } from 'node:fs';
import { lstat, mkdtemp, open, readlink, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const decoder = new TextDecoder('utf-8', { fatal: true });

/**
 * Observe a Git checkout without trusting its mutable index, replacement refs,
 * local clean filters, attributes, or filemode configuration. Canonical tree
 * entries are compared directly with raw worktree bytes and executable modes.
 */
export async function inspectGitState(root, { includeUntracked = false, signal } = {}) {
  signal?.throwIfAborted();
  const candidateRoot = await realpath(path.resolve(root));
  const common = [
    '--no-lazy-fetch',
    '-c', 'core.attributesFile=/dev/null',
    '-c', 'core.excludesFile=/dev/null',
    '-c', 'core.filemode=true',
    '-c', 'core.fsmonitor=false',
    '-c', 'core.ignoreCase=false',
    '-c', 'core.sparseCheckout=false',
    '-c', 'core.symlinks=true',
    '-c', 'core.untrackedCache=false',
    '-c', 'index.sparse=false',
    '-C', candidateRoot,
  ];
  const baseOptions = {
    encoding: 'utf8',
    timeout: 10_000,
    maxBuffer: 16 * 1024 * 1024,
    env: {
      PATH: process.env.PATH,
      LC_ALL: 'C',
      LANG: 'C',
      GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null',
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_NO_LAZY_FETCH: '1',
      GIT_NO_REPLACE_OBJECTS: '1',
      GIT_OPTIONAL_LOCKS: '0',
      GIT_TERMINAL_PROMPT: '0',
    },
    ...(signal ? { signal } : {}),
  };
  const { stdout: headOutput } = await execFileAsync(
    'git',
    [...common, 'rev-parse', '--verify', 'HEAD'],
    baseOptions,
  );
  const head = headOutput.trim();
  const [{ stdout: top }, { stdout: tree }, { stdout: type }] = await Promise.all([
    execFileAsync('git', [...common, 'rev-parse', '--show-toplevel'], baseOptions),
    execFileAsync('git', [...common, 'rev-parse', '--verify', `${head}^{tree}`], baseOptions),
    execFileAsync('git', [...common, 'cat-file', '-t', head], baseOptions),
  ]);
  if (await realpath(top.trim()) !== candidateRoot) {
    throw new Error('Candidate root must be the Git worktree top level');
  }
  if (type.trim() !== 'commit') throw new Error('Candidate HEAD must resolve to a Git commit');
  const algorithm = head.length === 40 ? 'sha1' : head.length === 64 ? 'sha256' : undefined;
  if (!algorithm) throw new Error('Candidate HEAD uses an unsupported Git object format');

  const { stdout: rawTree } = await execFileAsync(
    'git',
    [...common, 'ls-tree', '-r', '-z', '--full-tree', `${head}^{tree}`],
    { ...baseOptions, encoding: 'buffer' },
  );
  const entries = parseTree(rawTree);
  let workingTreeClean = true;
  for (const entry of entries) {
    signal?.throwIfAborted();
    if (!await matchesWorktreeEntry(candidateRoot, entry, algorithm, includeUntracked, signal)) {
      workingTreeClean = false;
      break;
    }
  }

  if (workingTreeClean && includeUntracked) {
    const temporary = await mkdtemp(path.join(os.tmpdir(), 'sprintloop-assurance-git-index-'));
    try {
      const receiverIndex = path.join(temporary, 'index');
      const receiverOptions = {
        ...baseOptions,
        encoding: 'buffer',
        env: { ...baseOptions.env, GIT_INDEX_FILE: receiverIndex },
      };
      await execFileAsync('git', [...common, 'read-tree', '--reset', `${head}^{tree}`], receiverOptions);
      const { stdout: untracked } = await execFileAsync('git', [
        ...common,
        'ls-files',
        '--others',
        '-z',
        '--exclude-per-directory=.gitignore',
      ], receiverOptions);
      workingTreeClean = untracked.length === 0;
    } finally {
      await rm(temporary, { recursive: true, force: true });
    }
  }

  const { stdout: confirmedHeadOutput } = await execFileAsync(
    'git',
    [...common, 'rev-parse', '--verify', 'HEAD'],
    baseOptions,
  );
  signal?.throwIfAborted();
  if (confirmedHeadOutput.trim() !== head) throw new Error('Candidate HEAD changed during Git inspection');
  return { head, tree: tree.trim(), workingTreeClean };
}

function parseTree(buffer) {
  const result = [];
  let offset = 0;
  while (offset < buffer.length) {
    const end = buffer.indexOf(0, offset);
    if (end < 0) throw new Error('Git tree inventory is not NUL terminated');
    const record = buffer.subarray(offset, end);
    offset = end + 1;
    const tab = record.indexOf(9);
    if (tab < 1) throw new Error('Git tree inventory entry is malformed');
    const [mode, type, objectId, ...extra] = record.subarray(0, tab).toString('ascii').split(' ');
    if (extra.length || !/^(?:100644|100755|120000|160000)$/.test(mode)
      || !/^(?:blob|commit)$/.test(type) || !/^[0-9a-f]{40,64}$/.test(objectId)) {
      throw new Error('Git tree inventory entry is unsupported');
    }
    let relative;
    try {
      relative = decoder.decode(record.subarray(tab + 1));
    } catch {
      throw new Error('Git tree contains a non-UTF-8 path');
    }
    const segments = relative.split('/');
    // Backslash is a valid POSIX filename byte but a Windows path separator.
    // Reject it everywhere so one Git tree has the same bounded interpretation
    // on every supported host.
    if (!relative || relative.includes('\\') || path.isAbsolute(relative)
      || segments.some((segment) => !segment || segment === '.' || segment === '..')) {
      throw new Error('Git tree contains an unsafe path');
    }
    result.push({ mode, type, objectId, relative, segments });
  }
  return result;
}

async function matchesWorktreeEntry(root, entry, algorithm, includeUntracked, signal) {
  signal?.throwIfAborted();
  const absolute = path.resolve(root, ...entry.segments);
  const relative = path.relative(root, absolute);
  if (!relative || path.isAbsolute(relative) || relative === '..' || relative.startsWith(`..${path.sep}`)) return false;
  try {
    const ancestors = await bindDirectoryAncestors(root, entry.segments.slice(0, -1));
    let matches;
    if (entry.mode === '160000') {
      const submodule = await lstat(absolute);
      if (!submodule.isDirectory() || submodule.isSymbolicLink()) return false;
      const nested = await inspectGitState(absolute, { includeUntracked, signal });
      matches = nested.head === entry.objectId && nested.workingTreeClean;
    } else if (entry.mode === '120000') {
      matches = await matchesSymlink(absolute, entry.objectId, algorithm);
    } else {
      matches = await matchesRegularFile(absolute, entry, algorithm, signal);
    }
    return matches && await directoryAncestorsUnchanged(ancestors);
  } catch (error) {
    if (['ENOENT', 'ENOTDIR', 'ELOOP'].includes(error?.code)) return false;
    throw error;
  }
}

async function bindDirectoryAncestors(root, segments) {
  const result = [];
  let current = root;
  for (const segment of ['', ...segments]) {
    if (segment) current = path.join(current, segment);
    const stat = await lstat(current);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw Object.assign(new Error('Candidate path has a non-directory ancestor'), { code: 'ENOTDIR' });
    result.push({ path: current, stat });
  }
  return result;
}

async function directoryAncestorsUnchanged(ancestors) {
  for (const ancestor of ancestors) {
    const after = await lstat(ancestor.path);
    if (!after.isDirectory() || after.isSymbolicLink() || !sameIdentity(ancestor.stat, after)) return false;
  }
  return true;
}

async function matchesSymlink(absolute, expectedObjectId, algorithm) {
  const before = await lstat(absolute);
  if (!before.isSymbolicLink()) return false;
  const target = await readlink(absolute, { encoding: 'buffer' });
  const after = await lstat(absolute);
  return sameIdentity(before, after) && gitBlobDigest(target, algorithm) === expectedObjectId;
}

async function matchesRegularFile(absolute, entry, algorithm, signal) {
  signal?.throwIfAborted();
  const handle = await open(
    absolute,
    constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0),
  );
  try {
    const before = await handle.stat();
    if (!before.isFile()) return false;
    const actualMode = (before.mode & 0o111) === 0 ? '100644' : '100755';
    if (actualMode !== entry.mode) return false;
    const hash = createHash(algorithm);
    hash.update(Buffer.from(`blob ${before.size}\0`, 'utf8'));
    const stream = handle.createReadStream({ autoClose: false, ...(signal ? { signal } : {}) });
    for await (const chunk of stream) hash.update(chunk);
    signal?.throwIfAborted();
    const after = await handle.stat();
    return sameIdentity(before, after) && hash.digest('hex') === entry.objectId;
  } finally {
    await handle.close();
  }
}

function gitBlobDigest(bytes, algorithm) {
  return createHash(algorithm)
    .update(Buffer.from(`blob ${bytes.length}\0`, 'utf8'))
    .update(bytes)
    .digest('hex');
}

function sameIdentity(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeMs === right.mtimeMs;
}
