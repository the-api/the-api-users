import { expect, test, describe } from 'bun:test';
import { testClient } from 'the-api';
import { login, migrationDir } from '../src';

const { theAPI, client, db } = await testClient({
  routingOptions: { migrationDirs: [migrationDir] },
  routings: [login],
});

describe('Login', () => {
  const authUser = {
    email: 'auth-user-1@test.local',
    password: 'auth-pass-1',
    fullName: 'Auth User',
  };
  const authUpdatedEmail = 'auth-user-1-updated@test.local';
  const authUpdatedEmailSecond = 'auth-user-1-updated-2@test.local';
  const authPhone = '+15550000001';

  let authToken = '';
  let authRefresh = '';

  test('init', async () => {
    await client.deleteTables();
    await theAPI.init();
  });

  test('users table has auth/recovery columns', async () => {
    const columns = await db('users').columnInfo();

    expect(!!columns.refresh).toEqual(true);
    expect(!!columns.timeRefreshExpired).toEqual(true);
    expect(!!columns.emailToChange).toEqual(true);
    expect(!!columns.isEmailVerified).toEqual(true);

    expect(!!columns.registerCode).toEqual(true);
    expect(!!columns.timeRegisterCodeExpired).toEqual(true);
    expect(!!columns.registerCodeAttempts).toEqual(true);

    expect(!!columns.recoverCode).toEqual(true);
    expect(!!columns.timeRecoverCodeExpired).toEqual(true);
    expect(!!columns.recoverCodeAttempts).toEqual(true);

    expect(!!columns.emailChangeCode).toEqual(true);
    expect(!!columns.timeEmailChangeCodeExpired).toEqual(true);
    expect(!!columns.emailChangeCodeAttempts).toEqual(true);

    expect(!!columns.phoneToChange).toEqual(true);
    expect(!!columns.phoneChangeCode).toEqual(true);
    expect(!!columns.timePhoneChangeCodeExpired).toEqual(true);
    expect(!!columns.phoneChangeCodeAttempts).toEqual(true);
  });

  test('POST /login/register', async () => {
    const { result } = await client.post('/login/register', authUser);

    expect(result.ok).toEqual(true);
    expect(result.email).toEqual(authUser.email);
    expect(result.role).toEqual('unverified');
    expect(result.emailConfirmationRequired).toEqual(true);
  });

  test('POST /login before email confirm', async () => {
    const { result } = await client.post('/login', authUser);
    expect(result.name).toEqual('EMAIL_NOT_CONFIRMED');
  });

  test('POST /login/register/confirm', async () => {
    const user = await db('users')
      .where({ email: authUser.email })
      .first();

    const { result } = await client.post('/login/register/confirm', {
      email: authUser.email,
      code: user.registerCode,
    });

    authToken = result.token;
    authRefresh = result.refresh;

    expect(result.isEmailVerified).toEqual(true);
    expect(result.role).toEqual('registered');
    expect(typeof result.token).toEqual('string');
    expect(typeof result.refresh).toEqual('string');
    expect(result.token.split('.').length).toEqual(3);
  });

  test('POST /login', async () => {
    const { result } = await client.post('/login', authUser);

    authToken = result.token;
    authRefresh = result.refresh;

    expect(typeof result.token).toEqual('string');
    expect(typeof result.refresh).toEqual('string');
    expect(result.token.split('.').length).toEqual(3);
    expect(result.refresh.length > 10).toEqual(true);
  });

  test('POST /login/refresh', async () => {
    const { result } = await client.post('/login/refresh', { refresh: authRefresh });

    expect(typeof result.token).toEqual('string');
    expect(typeof result.refresh).toEqual('string');
    expect(result.token.split('.').length).toEqual(3);
    expect(result.refresh).toEqual(authRefresh);
  });

  test('POST /login/forgot', async () => {
    const { result } = await client.post('/login/forgot', { email: authUser.email });

    expect(result.ok).toEqual(true);
  });

  test('POST /login/restore with wrong code', async () => {
    const { result } = await client.post('/login/restore', {
      code: 'wrong-code',
      password: 'auth-pass-2',
    });

    expect(result.name).toEqual('WRONG_CODE');
  });

  test('POST /login/restore with correct code', async () => {
    const user = await db('users')
      .where({ email: authUser.email })
      .first();

    const { result } = await client.post('/login/restore', {
      code: user.recoverCode,
      password: 'auth-pass-2',
    });

    expect(result.ok).toEqual(true);
  });

  test('POST /login with restored password', async () => {
    const { result } = await client.post('/login', {
      email: authUser.email,
      password: 'auth-pass-2',
    });

    authToken = result.token;
    authRefresh = result.refresh;

    expect(typeof result.token).toEqual('string');
    expect(typeof result.refresh).toEqual('string');
  });

  test('PATCH /login { email }', async () => {
    const { result } = await client.patch('/login', { email: authUpdatedEmail }, authToken);

    expect(result.ok).toEqual(true);
    expect(result.emailChangeRequested).toEqual(true);
  });

  test('changing email does not downgrade registered role', async () => {
    const user = await db('users')
      .where({ email: authUser.email })
      .first();

    expect(user.role).toEqual('registered');
    expect(user.isEmailVerified).toEqual(true);
  });

  test('POST /login/email with wrong code', async () => {
    const { result } = await client.post('/login/email', { code: 'wrong-code' }, authToken);

    expect(result.name).toEqual('INVALID_OR_EXPIRED_CODE');
  });

  test('POST /login/email with correct code', async () => {
    const user = await db('users')
      .where({ email: authUser.email })
      .first();

    const { result } = await client.post('/login/email', { code: user.emailChangeCode }, authToken);

    authToken = result.token;
    authRefresh = result.refresh;

    expect(result.email).toEqual(authUpdatedEmail);
    expect(result.role).toEqual('registered');
  });

  test('confirming email upgrades only unverified role', async () => {
    await db('users')
      .where({ email: authUpdatedEmail })
      .update({
        role: 'admin',
        emailToChange: authUpdatedEmailSecond,
        emailChangeCode: '112233',
        emailChangeCodeAttempts: 0,
        timeEmailChangeCodeExpired: new Date(Date.now() + 60_000),
        isEmailVerified: false,
      });

    const { result } = await client.post('/login/email', { code: '112233' }, authToken);

    authToken = result.token;
    authRefresh = result.refresh;

    expect(result.email).toEqual(authUpdatedEmailSecond);
    expect(result.role).toEqual('admin');
  });

  test('PATCH /login { phone }', async () => {
    const { result } = await client.patch('/login', { phone: authPhone }, authToken);

    expect(result.ok).toEqual(true);
    expect(result.phoneChangeRequested).toEqual(true);
  });

  test('POST /login/phone with correct code', async () => {
    const user = await db('users')
      .where({ email: authUpdatedEmailSecond })
      .first();

    const { result } = await client.post('/login/phone', { code: user.phoneChangeCode }, authToken);

    authToken = result.token;
    authRefresh = result.refresh;

    expect(result.phone).toEqual(authPhone);
    expect(result.isPhoneVerified).toEqual(true);
  });

  test('GET /login/me', async () => {
    const { result } = await client.get('/login/me', authToken);

    expect(result.email).toEqual(authUpdatedEmailSecond);
    expect(result.phone).toEqual(authPhone);
  });

  test('finalize', async () => {
    await client.deleteTables();
  });
});
