import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const moduleDir = dirname(fileURLToPath(import.meta.url));
const migrationDir = resolve(moduleDir, '../migrations');

export { migrationDir };
export { login } from './modules/login';
export { users } from './modules/users';
