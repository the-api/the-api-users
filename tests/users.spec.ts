import { expect, test, describe } from 'bun:test';
import { middlewares, testClient } from 'the-api';

import { users, migrationDir } from '../src';

const roles = {
  root: ['*'],
  admin: [
    'users.get',
    'users.post',
    'users.patch',
    'users.delete',
    'users.viewEmail',
    'users.viewPhone',
    'users.viewRole',
    'users.viewLocale',
    'users.viewStatus',
    'users.viewMeta',
    'users.editProfile',
    'users.editEmail',
    'users.editPhone',
    'users.editRole',
    'users.editStatus',
    'users.editVerification',
    'users.uploadAvatar',
  ],
  registered: ['users.get'],
  owner: [
    'users.viewEmail',
    'users.viewPhone',
    'users.viewRole',
    'users.viewLocale',
    'users.viewMeta',
  ],
};

const { theAPI, client, tokens, users: testUsers } = await testClient({
  migrationDirs: [migrationDir],
  routings: [middlewares.files, users],
  roles,
});

describe('Users', () => {
  const user = {
    email: 'user-1@test.local',
    password: 'pass-1',
    fullName: 'User One',
    locale: 'uk',
    timezone: 'Europe/Kyiv',
  };
  const updatedUserEmail = 'user-1-updated@test.local';

  let userId = 1;
  let ownerUserId = testUsers.registered.id;

  test('init', async () => {
    await client.deleteTables();
    await theAPI.init();
  });

  test('prepare owner user for owner-permission checks', async () => {
    await client.db('users').insert({
      id: ownerUserId,
      email: 'owner-user@test.local',
      password: 'owner-hash',
      salt: 'owner-salt',
      fullName: 'Owner User',
      phone: '+15551111111',
      isEmailVerified: true,
      isPhoneVerified: true,
      role: 'registered',
    });

    const owner = await client.db('users').where({ id: ownerUserId }).first();
    expect(owner.email).toEqual('owner-user@test.local');
  });

  test('GET /users by no token', async () => {
    const { result } = await client.get('/users', tokens.noToken);

    expect(result.name).toEqual('ACCESS_DENIED');
  });

  test('POST /users by registered token', async () => {
    const { result } = await client.post('/users', user, tokens.registered);

    expect(result.name).toEqual('ACCESS_DENIED');
  });

  test('POST /users by admin token', async () => {
    const { result } = await client.post('/users', user, tokens.admin);

    userId = result.id;
    expect(result.email).toEqual(user.email);
    expect(result.role).toEqual('unverified');
    expect(result.password).toEqual(undefined);
    expect(result.salt).toEqual(undefined);
  });

  test('GET /users by registered token', async () => {
    const { result, meta } = await client.get('/users?_sort=id', tokens.registered);

    expect(meta.total).toEqual(2);
    expect(result[0].email).toEqual(undefined);
    expect(result[0].phone).toEqual(undefined);
    expect(result[0].password).toEqual(undefined);
    expect(result[0].salt).toEqual(undefined);
  });

  test('GET /users by admin token', async () => {
    const { result, meta } = await client.get('/users?_sort=id', tokens.admin);

    expect(meta.total).toEqual(2);
    expect(result.find((item: any) => item.id === userId)?.email).toEqual(user.email);
  });

  test('GET /users/:id by owner token exposes own private fields', async () => {
    const { result } = await client.get(`/users/${ownerUserId}`, tokens.registered);

    expect(result.email).toEqual('owner-user@test.local');
    expect(result.phone).toEqual('+15551111111');
    expect(result.password).toEqual(undefined);
  });

  test('PATCH /users/:id by registered token', async () => {
    const { result } = await client.patch(`/users/${userId}`, { email: updatedUserEmail }, tokens.registered);

    expect(result.name).toEqual('ACCESS_DENIED');
  });

  test('PATCH /users/:id by admin token', async () => {
    const { result } = await client.patch(
      `/users/${userId}`,
      { email: updatedUserEmail, fullName: 'Updated User', isEmailVerified: false },
      tokens.admin,
    );

    expect(result.email).toEqual(updatedUserEmail);
    expect(result.fullName).toEqual('Updated User');
  });

  test('PATCH /users/:id by admin refreshes verification data for changed email', async () => {
    const result = await client.db('users').where({ id: userId }).first();

    expect(result.isEmailVerified).toEqual(false);
    expect(result.role).toEqual('unverified');
    expect(typeof result.registerCode).toEqual('string');
  });

  test('PATCH /users/:id email reset keeps non-unverified role', async () => {
    await client.db('users')
      .where({ id: userId })
      .update({
        role: 'admin',
        isEmailVerified: true,
      });

    await client.patch(
      `/users/${userId}`,
      { email: 'user-1-admin-kept@test.local', isEmailVerified: false },
      tokens.admin,
    );

    const result = await client.db('users').where({ id: userId }).first();

    expect(result.isEmailVerified).toEqual(false);
    expect(result.role).toEqual('admin');
  });

  test('POST /users/:id/avatar by owner token', async () => {
    const avatar = await client.readFile('./tests/static/1.png');
    const response = await client.postFormRequest(`/users/${ownerUserId}/avatar`, { avatar }, tokens.registered);
    const json = await response?.json();

    expect(typeof json.result.avatar).toEqual('string');
  });

  test('DELETE /users/:id by registered token', async () => {
    const { result } = await client.delete(`/users/${userId}`, tokens.registered);

    expect(result.name).toEqual('ACCESS_DENIED');
  });

  test('DELETE /users/:id by admin token', async () => {
    const { result } = await client.delete(`/users/${userId}`, tokens.admin);

    expect(result.ok).toEqual(true);
  });

  test('GET /users/:id after delete', async () => {
    const { result } = await client.get(`/users/${userId}`, tokens.admin);

    expect(result.name).toEqual('NOT_FOUND');
  });

  test('finalize', async () => {
    await client.deleteTables();
  });
});
