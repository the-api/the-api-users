import { TheAPI, middlewares } from 'the-api'
import { login, users } from './src';

const theAPI = new TheAPI({
  routings: [
    middlewares.logs,
    middlewares.errors,
    middlewares.email,
    middlewares.files,
    login,
    users,
  ],
});

await theAPI.up();
