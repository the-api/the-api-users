import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const moduleDir = dirname(fileURLToPath(import.meta.url));
const migrationDir = resolve(moduleDir, '../migrations');
const migrationUpdateDir = resolve(moduleDir, '../migrationsUpdate');

export { migrationDir, migrationUpdateDir };
export { login } from './modules/login';
export { users } from './modules/users';
