import {
  createHash,
  createHmac,
  randomBytes,
  scryptSync,
  timingSafeEqual,
} from 'node:crypto';

export type JwtPayload = {
  id: number | string;
  role?: string | null;
  roles: string[];
  email?: string | null;
  fullName?: string | null;
  phone?: string | null;
  [key: string]: unknown;
};

export type PasswordHashAlgorithm = 'scrypt' | 'sha256';
export type PasswordScryptOptions = {
  N: number;
  r: number;
  p: number;
  maxmem: number;
};

const ONE_SECOND = 1000;
const DEFAULT_PASSWORD_HASH_ALGORITHM: PasswordHashAlgorithm = 'scrypt';
const DEFAULT_SCRYPT_OPTIONS: PasswordScryptOptions = {
  N: 16_384,
  r: 8,
  p: 1,
  maxmem: 32 * 1024 * 1024,
};
const DURATION_UNITS: Record<string, number> = {
  s: 1,
  m: 60,
  h: 60 * 60,
  d: 24 * 60 * 60,
};

const base64UrlEncode = (value: string | Buffer): string =>
  Buffer.from(value)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');

const getDurationSeconds = (value: string | number | undefined, fallback: number): number => {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return Math.max(1, Math.floor(value));
  }

  if (typeof value !== 'string' || !value.trim()) return fallback;

  const trimmed = value.trim();
  const plain = Number(trimmed);
  if (Number.isFinite(plain)) return Math.max(1, Math.floor(plain));

  const match = trimmed.match(/^(\d+)([smhd])$/i);
  if (!match) return fallback;

  const amount = Number(match[1]);
  const unit = DURATION_UNITS[match[2].toLowerCase()];
  if (!Number.isFinite(amount) || !unit) return fallback;
  return amount * unit;
};

export const getExpiresAt = (value: string | number | undefined, fallback: number): Date =>
  new Date(Date.now() + getDurationSeconds(value, fallback) * ONE_SECOND);

export const isExpired = (value: Date | string | null | undefined): boolean => {
  if (!value) return true;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) || date.getTime() <= Date.now();
};

export const randomToken = (bytes = 32): string => base64UrlEncode(randomBytes(bytes));

export const randomCode = (length = 6): string => {
  const numbers = Array.from({ length }, () => Math.floor(Math.random() * 10));
  return numbers.join('');
};

export const randomSalt = (): string => randomToken(16);

export const getPasswordHashAlgorithm = (): PasswordHashAlgorithm => {
  const value = process.env.AUTH_PASSWORD_HASH_ALGORITHM?.trim().toLowerCase();
  if (value === 'sha256') return 'sha256';
  return DEFAULT_PASSWORD_HASH_ALGORITHM;
};

const isPowerOfTwo = (value: number): boolean =>
  value > 1 && Number.isInteger(Math.log2(value));

const getIntegerEnv = (
  key: string,
  fallback: number,
  isValid: (value: number) => boolean = (value) => value > 0,
): number => {
  const raw = process.env[key]?.trim();
  if (!raw) return fallback;

  const value = Number(raw);
  return Number.isSafeInteger(value) && isValid(value) ? value : fallback;
};

export const getScryptOptions = (): PasswordScryptOptions => ({
  N: getIntegerEnv('AUTH_SCRYPT_N', DEFAULT_SCRYPT_OPTIONS.N, isPowerOfTwo),
  r: getIntegerEnv('AUTH_SCRYPT_R', DEFAULT_SCRYPT_OPTIONS.r),
  p: getIntegerEnv('AUTH_SCRYPT_P', DEFAULT_SCRYPT_OPTIONS.p),
  maxmem: getIntegerEnv('AUTH_SCRYPT_MAXMEM', DEFAULT_SCRYPT_OPTIONS.maxmem),
});

export const hashPassword = (
  password: string,
  salt: string,
  algorithm = getPasswordHashAlgorithm(),
): string => {
  if (algorithm === 'sha256') {
    return createHash('sha256').update(`${password}${salt}`, 'utf8').digest('hex');
  }

  return scryptSync(password, salt, 64, getScryptOptions()).toString('hex');
};

export const verifyPassword = (
  password: string,
  salt: string,
  hash: string,
  algorithm = getPasswordHashAlgorithm(),
): boolean => {
  const expected = Buffer.from(hash, 'hex');
  const actual = Buffer.from(hashPassword(password, salt, algorithm), 'hex');

  if (expected.length !== actual.length) return false;
  return timingSafeEqual(expected, actual);
};

export const normalizeEmail = (value: unknown): string | null => {
  if (typeof value !== 'string') return null;
  const email = value.trim().toLowerCase();
  return email || null;
};

export const normalizePhone = (value: unknown): string | null => {
  if (typeof value !== 'string') return null;

  const trimmed = value.trim();
  if (!trimmed) return null;

  const normalized = trimmed.replace(/[^\d+]/g, '');
  if (!normalized) return null;

  if (normalized.startsWith('+')) {
    return `+${normalized.slice(1).replace(/\D/g, '')}` || null;
  }

  return normalized.replace(/\D/g, '') || null;
};

export const signJwt = (
  payload: JwtPayload,
  {
    secret = process.env.JWT_SECRET || '',
    expiresIn = process.env.JWT_EXPIRES_IN || '1h',
  }: {
    secret?: string;
    expiresIn?: string | number;
  } = {},
): string => {
  const now = Math.floor(Date.now() / ONE_SECOND);
  const exp = now + getDurationSeconds(expiresIn, 60 * 60);
  const header = { alg: 'HS256', typ: 'JWT' };
  const body = { ...payload, iat: now, exp };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(body));
  const signature = createHmac('sha256', secret)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest();

  return `${encodedHeader}.${encodedPayload}.${base64UrlEncode(signature)}`;
};
