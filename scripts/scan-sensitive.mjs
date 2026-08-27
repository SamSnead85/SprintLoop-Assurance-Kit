import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';

const root = process.cwd();
const excluded = new Set(['.git', 'node_modules']);
const patterns = [
  ['private-key', new RegExp(`BEGIN (?:RSA |EC |OPENSSH |DSA )?${'PRIVATE'} KEY`)],
  ['encrypted-private-key', new RegExp(`BEGIN ENCRYPTED ${'PRIVATE'} KEY`)],
  ['github-token', new RegExp(`gh[pousr]_[A-Za-z0-9]{30,}`)],
  ['github-fine-grained-token', new RegExp(`github_pat_[A-Za-z0-9_]{40,}`)],
  ['aws-access-key', new RegExp(`AKIA[0-9A-Z]{16}`)],
  ['slack-token', new RegExp(`xox[baprs]-[A-Za-z0-9-]{20,}`)],
  ['openai-token', new RegExp(`sk-${'proj'}-[A-Za-z0-9_-]{20,}`)],
  ['anthropic-token', new RegExp(`sk-${'ant'}-[A-Za-z0-9_-]{20,}`)],
  ['google-api-key', new RegExp(`AI${'za'}[A-Za-z0-9_-]{35}`)],
  ['npm-token', new RegExp(`n${'pm'}_[A-Za-z0-9]{30,}`)],
  ['pypi-token', new RegExp(`py${'pi'}-[A-Za-z0-9_-]{30,}`)],
  ['huggingface-token', new RegExp(`h${'f'}_[A-Za-z0-9]{30,}`)],
  ['stripe-live-key', new RegExp(`sk_${'live'}_[A-Za-z0-9]{20,}`)],
  ['generic-secret-assignment', new RegExp(`(?:api[_-]?key|client[_-]?secret|password)\\s*[:=]\\s*["'][^"']{12,}["']`, 'i')],
  ['local-user-path', new RegExp(`/(?:Users|home)/[^/\\s]+/`)],
  ['private-loopback-url', new RegExp(`https?://(?:127\\.0\\.0\\.1|localhost)(?::\\d+)?`, 'i')],
];
const allowedEmails = new Set(['security@sprintloop.ai']);
const findings = [];
const files = await walk(root);

for (const file of files) {
  const relative = path.relative(root, file);
  if (relative === 'scripts/scan-sensitive.mjs' || relative === 'package-lock.json') continue;
  const bytes = await readFile(file);
  // Latin-1 preserves every ASCII credential marker even inside an otherwise
  // binary file, so a NUL byte cannot turn the source scan into an implicit
  // allowlist. Ordinary text remains UTF-8 decoded for email/path checks.
  const content = bytes.includes(0) ? bytes.toString('latin1') : bytes.toString('utf8');
  for (const [label, pattern] of patterns) {
    if (pattern.test(content)) findings.push(`${relative}: ${label}`);
  }
  const emails = content.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi) ?? [];
  for (const email of emails) {
    if (!allowedEmails.has(email.toLowerCase())) findings.push(`${relative}: email-address`);
  }
}

if (findings.length) {
  process.stderr.write(`Sensitive-data gate failed:\n${[...new Set(findings)].map((entry) => `- ${entry}`).join('\n')}\n`);
  process.exit(1);
}
process.stdout.write(`Sensitive-data pattern gate: ${files.length} files checked; no configured credential or personal-data patterns found\n`);

async function walk(directory) {
  const output = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (excluded.has(entry.name)) continue;
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) output.push(...await walk(absolute));
    else output.push(absolute);
  }
  return output;
}
