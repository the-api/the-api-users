import { createHash, scryptSync } from 'node:crypto';
import { afterEach, describe, expect, test } from 'bun:test';

import {
  getPasswordHashAlgorithm,
  getScryptOptions,
  hashPassword,
  verifyPassword,
} from '../src/lib/auth';

const envKeys = [
  'AUTH_PASSWORD_HASH_ALGORITHM',
  'AUTH_SCRYPT_N',
  'AUTH_SCRYPT_R',
  'AUTH_SCRYPT_P',
  'AUTH_SCRYPT_MAXMEM',
] as const;
const originalEnv = new Map(envKeys.map((key) => [key, process.env[key]]));
const scryptEnvKeys = envKeys.filter((key) => key.startsWith('AUTH_SCRYPT_'));

const clearScryptEnv = () => {
  for (const key of scryptEnvKeys) delete process.env[key];
};

afterEach(() => {
  for (const key of envKeys) {
    const value = originalEnv.get(key);
    if (value === undefined) {
      delete process.env[key];
      continue;
    }

    process.env[key] = value;
  }
});

describe('auth password hashing', () => {
  const password = 'auth-pass-1';
  const salt = '22acdf42-5a61-4788-92c8-3fd41c9ca596';

  test('uses scrypt hashes by default', () => {
    delete process.env.AUTH_PASSWORD_HASH_ALGORITHM;
    clearScryptEnv();

    const expected = scryptSync(password, salt, 64).toString('hex');
    const hash = hashPassword(password, salt);

    expect(getPasswordHashAlgorithm()).toEqual('scrypt');
    expect(hash).toEqual(expected);
    expect(hash.length).toEqual(128);
    expect(verifyPassword(password, salt, hash)).toEqual(true);
    expect(verifyPassword('wrong-pass', salt, hash)).toEqual(false);
  });

  test('uses scrypt parameters from env', () => {
    process.env.AUTH_SCRYPT_N = '1024';
    process.env.AUTH_SCRYPT_R = '4';
    process.env.AUTH_SCRYPT_P = '1';
    process.env.AUTH_SCRYPT_MAXMEM = `${64 * 1024 * 1024}`;

    const options = getScryptOptions();
    const expected = scryptSync(password, salt, 64, options).toString('hex');
    const hash = hashPassword(password, salt);

    expect(options).toEqual({
      N: 1024,
      r: 4,
      p: 1,
      maxmem: 64 * 1024 * 1024,
    });
    expect(hash).toEqual(expected);
    expect(verifyPassword(password, salt, hash)).toEqual(true);
  });

  test('falls back to default scrypt parameters for invalid env values', () => {
    process.env.AUTH_SCRYPT_N = '1000';
    process.env.AUTH_SCRYPT_R = '0';
    process.env.AUTH_SCRYPT_P = 'nope';
    process.env.AUTH_SCRYPT_MAXMEM = '-1';

    expect(getScryptOptions()).toEqual({
      N: 16_384,
      r: 8,
      p: 1,
      maxmem: 32 * 1024 * 1024,
    });
  });

  test('supports legacy sha256 password hashes from env', () => {
    process.env.AUTH_PASSWORD_HASH_ALGORITHM = 'sha256';
    clearScryptEnv();

    const expected = createHash('sha256')
      .update(`${password}${salt}`, 'utf8')
      .digest('hex');
    const hash = hashPassword(password, salt);

    expect(getPasswordHashAlgorithm()).toEqual('sha256');
    expect(hash).toEqual(expected);
    expect(hash.length).toEqual(64);
    expect(verifyPassword(password, salt, hash)).toEqual(true);
    expect(verifyPassword('wrong-pass', salt, hash)).toEqual(false);
  });

  test('normalizes password hash algorithm env value', () => {
    process.env.AUTH_PASSWORD_HASH_ALGORITHM = ' SHA256 ';

    expect(getPasswordHashAlgorithm()).toEqual('sha256');
  });
});
