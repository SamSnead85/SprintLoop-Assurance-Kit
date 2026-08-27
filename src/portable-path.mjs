const CONTROL = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/u;
const WINDOWS_DEVICE = /^(?:con|prn|aux|nul|com[1-9¹²³]|lpt[1-9¹²³])(?:[ .]|$)/iu;

// JSON Schema has no portable way to attach a case-insensitive flag. Spell
// device names explicitly so runtime and published schemas reject the same
// cross-platform aliases, including NTFS alternate-data-stream syntax.
export const PORTABLE_RELATIVE_PATH_PATTERN = '^(?!/)(?!.*\\\\)(?!.*:)(?!.*[<>"|?*])(?!.*//)(?!.*(?:^|/)(?:\\.|\\.\\.)(?:/|$))(?!.*(?:^|/)(?:[Cc][Oo][Nn]|[Pp][Rr][Nn]|[Aa][Uu][Xx]|[Nn][Uu][Ll]|[Cc][Oo][Mm][1-9¹²³]|[Ll][Pp][Tt][1-9¹²³])(?:[ .]|/|$))(?!.*[. ](?:/|$))(?!.*[\\u0000-\\u001f\\u007f-\\u009f\\u2028\\u2029]).{1,1024}$';

export function isPortableRelativePath(value, { allowDot = false, maxLength = 1024 } = {}) {
  if (allowDot && value === '.') return true;
  if (typeof value !== 'string' || value.length < 1 || value.length > maxLength * 2
    || [...value].length > maxLength) return false;
  if (value.startsWith('/') || value.includes('\\') || value.includes('//') || value.includes(':')
    || /[<>"|?*]/u.test(value) || CONTROL.test(value)) return false;
  return value.split('/').every((segment) => segment !== '' && segment !== '.' && segment !== '..'
    && !/[. ]$/u.test(segment) && !WINDOWS_DEVICE.test(segment));
}
