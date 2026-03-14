import { Routings } from 'the-api-routings';
import type { AppContext } from 'the-api-routings';
import {
  getExpiresAt,
  hashPassword,
  isExpired,
  normalizeEmail,
  normalizePhone,
  randomCode,
  randomSalt,
  randomToken,
  signJwt,
  verifyPassword,
} from '../lib/auth';
import {
  getDb,
  getDbWrite,
  getUserRoles,
  requireAuth,
  sendEmail,
  sendSms,
  type UserRecord,
} from '../lib/runtime';
import {
  USER_HIDDEN_FIELDS,
  USER_OWNER_PERMISSIONS,
  USER_VISIBLE_FOR,
  USER_SELF_EDITABLE_FIELDS,
} from '../lib/user-config';

const login = new Routings();

const CODE_EXPIRES_IN = process.env.AUTH_CODE_EXPIRES_IN || '30m';
const RECOVER_CODE_EXPIRES_IN = process.env.AUTH_RECOVER_CODE_EXPIRES_IN || CODE_EXPIRES_IN;
const REFRESH_EXPIRES_IN = process.env.AUTH_REFRESH_EXPIRES_IN || '30d';
const VERIFIED_ROLE = process.env.AUTH_VERIFIED_ROLE || process.env.AUTH_DEFAULT_ROLE || 'registered';
const UNVERIFIED_ROLE = process.env.AUTH_UNVERIFIED_ROLE || 'unverified';
const REQUIRE_EMAIL_VERIFICATION = process.env.AUTH_REQUIRE_EMAIL_VERIFICATION !== 'false';
const MAX_CODE_ATTEMPTS = Number(process.env.AUTH_MAX_CODE_ATTEMPTS || 5);

const LOGIN_ERRORS = {
  USER_NOT_FOUND: {
    code: 101,
    status: 404,
    description: 'User not found',
  },
  USER_ACCESS_DENIED: {
    code: 102,
    status: 403,
    description: 'User access denied',
  },
  EMAIL_EXISTS: {
    code: 103,
    status: 409,
    description: 'Email already exists',
  },
  PHONE_EXISTS: {
    code: 104,
    status: 409,
    description: 'Phone already exists',
  },
  LOGIN_EXISTS: {
    code: 105,
    status: 409,
    description: 'Login already exists',
  },
  EMAIL_NOT_CONFIRMED: {
    code: 106,
    status: 403,
    description: 'Email is not confirmed',
  },
  INVALID_OR_EXPIRED_CODE: {
    code: 107,
    status: 409,
    description: 'Code is invalid or expired',
  },
  WRONG_CODE: {
    code: 108,
    status: 409,
    description: 'Wrong code',
  },
  WRONG_PASSWORD: {
    code: 109,
    status: 409,
    description: 'Wrong password',
  },
  NO_TOKEN: {
    code: 110,
    status: 401,
    description: 'Token required',
  },
  INVALID_EMAIL: {
    code: 111,
    status: 400,
    description: 'Email is invalid',
  },
  INVALID_PHONE: {
    code: 112,
    status: 400,
    description: 'Phone is invalid',
  },
  PASSWORD_REQUIRED: {
    code: 113,
    status: 400,
    description: 'Password is required',
  },
  LOGIN_OR_EMAIL_REQUIRED: {
    code: 114,
    status: 400,
    description: 'Login or email is required',
  },
  NOTHING_TO_CONFIRM: {
    code: 115,
    status: 409,
    description: 'Nothing to confirm',
  },
  EMAIL_ALREADY_CONFIRMED: {
    code: 116,
    status: 409,
    description: 'Email is already confirmed',
  },
  SMS_SEND_FAILED: {
    code: 117,
    status: 502,
    description: 'SMS provider failed to deliver the message',
  },
} as const;

const AUTH_EMAIL_TEMPLATES = {
  login_register_code: {
    subject: 'Confirm your email',
    text: 'Use this code to confirm your email: {{code}}',
  },
  login_recover_code: {
    subject: 'Password recovery code',
    text: 'Use this code to restore your password: {{code}}',
  },
  login_email_change_code: {
    subject: 'Confirm your new email',
    text: 'Use this code to confirm your new email: {{code}}',
  },
};

const getRoleAfterEmailConfirmation = (role: string | null | undefined): string =>
  role === UNVERIFIED_ROLE || !role ? VERIFIED_ROLE : role;

const trimString = (value: unknown): string | null => {
  if (typeof value !== 'string') return null;
  const result = value.trim();
  return result || null;
};

const toPublicAuthUser = (user: Partial<UserRecord>) => ({
  id: user.id,
  email: user.email || null,
  phone: user.phone || null,
  fullName: user.fullName || null,
  role: user.role || (user.isEmailVerified ? VERIFIED_ROLE : UNVERIFIED_ROLE),
  roles: getUserRoles(user),
  avatar: user.avatar || null,
  locale: user.locale || null,
  timezone: user.timezone || null,
  isEmailVerified: !!user.isEmailVerified,
  isPhoneVerified: !!user.isPhoneVerified,
});

const findUserByEmail = async (c: AppContext, email: string): Promise<UserRecord | undefined> => {
  const db = getDb(c);
  return db('users')
    .whereRaw('LOWER(email) = ?', [email])
    .first() as Promise<UserRecord | undefined>;
};

const findUserByLogin = async (c: AppContext, loginName: string): Promise<UserRecord | undefined> => {
  const db = getDb(c);
  return db('users')
    .whereRaw('LOWER(login) = ?', [loginName.toLowerCase()])
    .first() as Promise<UserRecord | undefined>;
};

const findUserByRefresh = async (c: AppContext, refresh: string): Promise<UserRecord | undefined> => {
  const db = getDb(c);
  return db('users').where({ refresh }).first() as Promise<UserRecord | undefined>;
};

const findUserByRecoverCode = async (c: AppContext, code: string): Promise<UserRecord | undefined> => {
  const db = getDb(c);
  return db('users').where({ recoverCode: code }).first() as Promise<UserRecord | undefined>;
};

const assertUserActive = (user: UserRecord | undefined): UserRecord => {
  if (!user || user.isDeleted) throw new Error('USER_NOT_FOUND');
  if (user.isBlocked) throw new Error('USER_ACCESS_DENIED');
  return user;
};

const ensureEmailUnique = async (
  c: AppContext,
  email: string,
  exceptUserId?: number,
): Promise<void> => {
  const db = getDb(c);
  const query = db('users').whereRaw('LOWER(email) = ?', [email]);
  if (exceptUserId) query.whereNot({ id: exceptUserId });
  const existing = await query.first();
  if (existing) throw new Error('EMAIL_EXISTS');
};

const ensurePhoneUnique = async (
  c: AppContext,
  phone: string,
  exceptUserId?: number,
): Promise<void> => {
  const db = getDb(c);
  const query = db('users').where({ phone });
  if (exceptUserId) query.whereNot({ id: exceptUserId });
  const existing = await query.first();
  if (existing) throw new Error('PHONE_EXISTS');
};

const ensureLoginUnique = async (
  c: AppContext,
  loginName: string,
  exceptUserId?: number,
): Promise<void> => {
  const db = getDb(c);
  const query = db('users').whereRaw('LOWER(login) = ?', [loginName.toLowerCase()]);
  if (exceptUserId) query.whereNot({ id: exceptUserId });
  const existing = await query.first();
  if (existing) throw new Error('LOGIN_EXISTS');
};

const saveAuthResult = async (
  c: AppContext,
  user: UserRecord,
  refreshOverride?: string,
): Promise<void> => {
  const dbWrite = getDbWrite(c);
  const refresh = refreshOverride || user.refresh || randomToken();
  const timeRefreshExpired = getExpiresAt(REFRESH_EXPIRES_IN, 30 * 24 * 60 * 60);

  await dbWrite('users')
    .where({ id: user.id })
    .update({
      refresh,
      timeRefreshExpired,
      timeUpdated: dbWrite.fn.now(),
    });

  const token = signJwt({
    id: user.id,
    role: user.role || (user.isEmailVerified ? VERIFIED_ROLE : UNVERIFIED_ROLE),
    roles: getUserRoles(user),
    email: user.email || undefined,
    phone: user.phone || undefined,
    fullName: user.fullName || undefined,
  });

  c.set('result', {
    ...toPublicAuthUser(user),
    token,
    refresh,
  });
};

const setCode = async (
  c: AppContext,
  userId: number,
  {
    codeField,
    attemptsField,
    expiresField,
    code,
    expiresAt,
    extra = {},
  }: {
    codeField: keyof UserRecord;
    attemptsField: keyof UserRecord;
    expiresField: keyof UserRecord;
    code: string;
    expiresAt: Date;
    extra?: Partial<UserRecord>;
  },
): Promise<void> => {
  const dbWrite = getDbWrite(c);
  await dbWrite('users')
    .where({ id: userId })
    .update({
      [codeField]: code,
      [attemptsField]: 0,
      [expiresField]: expiresAt,
      ...extra,
      timeUpdated: dbWrite.fn.now(),
    });
};

const clearCode = async (
  c: AppContext,
  userId: number,
  {
    codeField,
    attemptsField,
    expiresField,
    extra = {},
  }: {
    codeField: keyof UserRecord;
    attemptsField: keyof UserRecord;
    expiresField: keyof UserRecord;
    extra?: Partial<UserRecord>;
  },
): Promise<void> => {
  const dbWrite = getDbWrite(c);
  await dbWrite('users')
    .where({ id: userId })
    .update({
      [codeField]: null,
      [attemptsField]: 0,
      [expiresField]: null,
      ...extra,
      timeUpdated: dbWrite.fn.now(),
    });
};

const failCodeAttempt = async (
  c: AppContext,
  user: UserRecord | undefined,
  attemptsField: keyof UserRecord,
  errorName = 'INVALID_OR_EXPIRED_CODE',
): Promise<never> => {
  if (user?.id) {
    const dbWrite = getDbWrite(c);
    await dbWrite('users')
      .where({ id: user.id })
      .update({
        [attemptsField]: Math.min(MAX_CODE_ATTEMPTS, Number(user[attemptsField] || 0) + 1),
        timeUpdated: dbWrite.fn.now(),
      });
  }

  throw new Error(errorName);
};

const verifyStoredCode = async (
  c: AppContext,
  user: UserRecord | undefined,
  {
    code,
    codeField,
    attemptsField,
    expiresField,
    errorName = 'INVALID_OR_EXPIRED_CODE',
  }: {
    code: string;
    codeField: keyof UserRecord;
    attemptsField: keyof UserRecord;
    expiresField: keyof UserRecord;
    errorName?: string;
  },
): Promise<UserRecord> => {
  if (!user) {
    throw new Error(errorName);
  }

  const savedCode = trimString(user[codeField]);
  const attempts = Number(user[attemptsField] || 0);
  const expiresAt = user[expiresField];

  if (!savedCode || attempts >= MAX_CODE_ATTEMPTS || isExpired(expiresAt as Date | string | null | undefined) || savedCode !== code) {
    await failCodeAttempt(c, user, attemptsField, errorName);
  }

  return user;
};

const sendRegisterCode = async (c: AppContext, user: UserRecord, code: string): Promise<void> => {
  if (!user.email) return;
  await sendEmail(c, {
    to: user.email,
    template: 'login_register_code',
    data: { code, email: user.email, fullName: user.fullName || '' },
  });
};

const sendRecoverCode = async (c: AppContext, user: UserRecord, code: string): Promise<void> => {
  if (!user.email) return;
  await sendEmail(c, {
    to: user.email,
    template: 'login_recover_code',
    data: { code, email: user.email, fullName: user.fullName || '' },
  });
};

const sendEmailChangeCode = async (c: AppContext, email: string, user: UserRecord, code: string): Promise<void> => {
  await sendEmail(c, {
    to: email,
    template: 'login_email_change_code',
    data: { code, email, fullName: user.fullName || '' },
  });
};

const sendPhoneConfirmationCode = async (c: AppContext, phone: string, code: string): Promise<void> => {
  await sendSms(c, {
    to: phone,
    body: `Your confirmation code is ${code}`,
  });
};

const getCurrentUserRecord = async (c: AppContext): Promise<UserRecord> => {
  const authUser = requireAuth(c);
  const db = getDb(c);
  const user = await db('users').where({ id: authUser.id }).first() as UserRecord | undefined;
  return assertUserActive(user);
};

const getConfirmationPayload = async (c: AppContext, target: 'email' | 'phone') => {
  const user = await getCurrentUserRecord(c);
  const code = trimString((await c.req.json<Record<string, unknown>>()).code);
  if (!code) throw new Error('INVALID_OR_EXPIRED_CODE');

  return { user, code };
};

login.errors(LOGIN_ERRORS);
login.emailTemplates(AUTH_EMAIL_TEMPLATES);

login.post('/login/register', async (c) => {
  const body = await c.req.json<Record<string, unknown>>();
  const email = normalizeEmail(body.email);
  const password = trimString(body.password);
  const phone = body.phone === undefined || body.phone === null ? null : normalizePhone(body.phone);
  const loginName = trimString(body.login);
  const fullName = trimString(body.fullName);
  const locale = trimString(body.locale);
  const timezone = trimString(body.timezone);

  if (!email) throw new Error('INVALID_EMAIL');
  if (!password) throw new Error('PASSWORD_REQUIRED');
  if (body.phone !== undefined && body.phone !== null && !phone) throw new Error('INVALID_PHONE');

  await ensureEmailUnique(c, email);
  if (phone) await ensurePhoneUnique(c, phone);
  if (loginName) await ensureLoginUnique(c, loginName);

  const dbWrite = getDbWrite(c);
  const salt = randomSalt();
  const passwordHash = hashPassword(password, salt);
  const registerCode = REQUIRE_EMAIL_VERIFICATION ? randomCode() : null;
  const timeRegisterCodeExpired = REQUIRE_EMAIL_VERIFICATION
    ? getExpiresAt(CODE_EXPIRES_IN, 30 * 60)
    : null;
  const phoneCode = phone ? randomCode() : null;
  const timePhoneCodeExpired = phone ? getExpiresAt(CODE_EXPIRES_IN, 30 * 60) : null;

  const [user] = await dbWrite('users')
    .insert({
      login: loginName,
      password: passwordHash,
      salt,
      timePasswordChanged: dbWrite.fn.now(),
      email,
      isEmailVerified: !REQUIRE_EMAIL_VERIFICATION,
      phone,
      isPhoneVerified: !phone,
      fullName,
      role: REQUIRE_EMAIL_VERIFICATION ? UNVERIFIED_ROLE : VERIFIED_ROLE,
      locale,
      timezone,
      registerCode,
      registerCodeAttempts: 0,
      timeRegisterCodeExpired,
      phoneCode,
      phoneCodeAttempts: 0,
      timePhoneCodeExpired,
    })
    .returning('*') as UserRecord[];

  if (registerCode) await sendRegisterCode(c, user, registerCode);
  if (phone && phoneCode) await sendPhoneConfirmationCode(c, phone, phoneCode);

  if (!REQUIRE_EMAIL_VERIFICATION) {
    await saveAuthResult(c, user);
    return;
  }

  c.set('result', {
    ...toPublicAuthUser(user),
    ok: true,
    emailConfirmationRequired: true,
    phoneConfirmationRequired: !!phone,
  });
});

const confirmRegistration = async (c: AppContext) => {
  const body = await c.req.json<Record<string, unknown>>();
  const email = normalizeEmail(body.email);
  const code = trimString(body.code);

  if (!email || !code) throw new Error('INVALID_OR_EXPIRED_CODE');

  const user = assertUserActive(await findUserByEmail(c, email));
  await verifyStoredCode(c, user, {
    code,
    codeField: 'registerCode',
    attemptsField: 'registerCodeAttempts',
    expiresField: 'timeRegisterCodeExpired',
  });

  const dbWrite = getDbWrite(c);
  await dbWrite('users')
    .where({ id: user.id })
    .update({
      isEmailVerified: true,
      role: getRoleAfterEmailConfirmation(user.role),
      registerCode: null,
      registerCodeAttempts: 0,
      timeRegisterCodeExpired: null,
      timeUpdated: dbWrite.fn.now(),
    });

  const refreshedUser = {
    ...user,
    role: getRoleAfterEmailConfirmation(user.role),
    isEmailVerified: true,
    registerCode: null,
    registerCodeAttempts: 0,
    timeRegisterCodeExpired: null,
  };

  await saveAuthResult(c, refreshedUser);
};

login.post('/login/register/confirm', confirmRegistration);
login.post('/login/register/check', confirmRegistration);

login.post('/login/register/resend', async (c) => {
  const body = await c.req.json<Record<string, unknown>>();
  const email = normalizeEmail(body.email);
  if (!email) throw new Error('INVALID_EMAIL');

  const user = assertUserActive(await findUserByEmail(c, email));
  if (user.isEmailVerified) throw new Error('EMAIL_ALREADY_CONFIRMED');

  const code = randomCode();
  await setCode(c, user.id, {
    codeField: 'registerCode',
    attemptsField: 'registerCodeAttempts',
    expiresField: 'timeRegisterCodeExpired',
    code,
    expiresAt: getExpiresAt(CODE_EXPIRES_IN, 30 * 60),
  });

  await sendRegisterCode(c, user, code);
  c.set('result', { ok: true });
});

login.post('/login', async (c) => {
  const body = await c.req.json<Record<string, unknown>>();
  const password = trimString(body.password);
  const email = normalizeEmail(body.email ?? body.login);
  const loginName = body.email ? null : trimString(body.login);

  if (!password) throw new Error('PASSWORD_REQUIRED');
  if (!email && !loginName) throw new Error('LOGIN_OR_EMAIL_REQUIRED');

  const user = assertUserActive(email
    ? await findUserByEmail(c, email)
    : await findUserByLogin(c, loginName as string));

  if (!user.password || !user.salt || !verifyPassword(password, user.salt, user.password)) {
    throw new Error('USER_NOT_FOUND');
  }

  if (REQUIRE_EMAIL_VERIFICATION && !user.isEmailVerified) {
    throw new Error('EMAIL_NOT_CONFIRMED');
  }

  await saveAuthResult(c, user, !isExpired(user.timeRefreshExpired) ? user.refresh || undefined : undefined);
});

const refreshHandler = async (c: AppContext) => {
  const body = c.req.method === 'GET'
    ? {}
    : await c.req.json<Record<string, unknown>>();
  const refresh = trimString(body.refresh) || trimString(c.req.query('refresh'));
  if (!refresh) throw new Error('USER_NOT_FOUND');

  const user = assertUserActive(await findUserByRefresh(c, refresh));
  if (!user.refresh || user.refresh !== refresh || isExpired(user.timeRefreshExpired)) {
    throw new Error('USER_NOT_FOUND');
  }

  if (REQUIRE_EMAIL_VERIFICATION && !user.isEmailVerified) {
    throw new Error('EMAIL_NOT_CONFIRMED');
  }

  await saveAuthResult(c, user, refresh);
};

login.post('/login/refresh', refreshHandler);
login.get('/login/refresh', refreshHandler);

login.post('/login/forgot', async (c) => {
  const body = await c.req.json<Record<string, unknown>>();
  const email = normalizeEmail(body.email ?? body.login);
  const loginName = body.email ? null : trimString(body.login);

  const user = email
    ? await findUserByEmail(c, email)
    : loginName
      ? await findUserByLogin(c, loginName)
      : undefined;

  if (!user || user.isDeleted || !user.email) {
    c.set('result', { ok: true });
    return;
  }

  const code = randomCode();
  await setCode(c, user.id, {
    codeField: 'recoverCode',
    attemptsField: 'recoverCodeAttempts',
    expiresField: 'timeRecoverCodeExpired',
    code,
    expiresAt: getExpiresAt(RECOVER_CODE_EXPIRES_IN, 30 * 60),
  });

  await sendRecoverCode(c, user, code);
  c.set('result', { ok: true });
});

login.post('/login/restore', async (c) => {
  const body = await c.req.json<Record<string, unknown>>();
  const code = trimString(body.code);
  const password = trimString(body.password);

  if (!code || !password) throw new Error('WRONG_CODE');

  const user = await findUserByRecoverCode(c, code);
  await verifyStoredCode(c, user, {
    code,
    codeField: 'recoverCode',
    attemptsField: 'recoverCodeAttempts',
    expiresField: 'timeRecoverCodeExpired',
    errorName: 'WRONG_CODE',
  });

  const dbWrite = getDbWrite(c);
  const salt = randomSalt();
  const passwordHash = hashPassword(password, salt);

  await dbWrite('users')
    .where({ id: user!.id })
    .update({
      password: passwordHash,
      salt,
      refresh: null,
      timeRefreshExpired: null,
      timePasswordChanged: dbWrite.fn.now(),
      recoverCode: null,
      recoverCodeAttempts: 0,
      timeRecoverCodeExpired: null,
      timeUpdated: dbWrite.fn.now(),
    });

  c.set('result', { ok: true });
});

login.patch('/login', async (c) => {
  const authUser = requireAuth(c);
  const body = await c.req.json<Record<string, unknown>>();
  const user = await getCurrentUserRecord(c);
  const dbWrite = getDbWrite(c);

  const updates: Partial<UserRecord> = {};
  let passwordChanged = false;
  let emailChangeRequested = false;
  let phoneChangeRequested = false;

  for (const field of USER_SELF_EDITABLE_FIELDS) {
    if (body[field] !== undefined) {
      updates[field as keyof UserRecord] = trimString(body[field]);
    }
  }

  const currentPassword = trimString(body.password);
  const newPassword = trimString(body.newPassword);

  if (currentPassword || newPassword) {
    if (!currentPassword || !newPassword || !user.password || !user.salt) {
      throw new Error('WRONG_PASSWORD');
    }

    if (!verifyPassword(currentPassword, user.salt, user.password)) {
      throw new Error('WRONG_PASSWORD');
    }

    const salt = randomSalt();
    updates.password = hashPassword(newPassword, salt);
    updates.salt = salt;
    updates.timePasswordChanged = dbWrite.fn.now() as unknown as Date;
    passwordChanged = true;
  }

  const nextEmail = body.email === undefined ? null : normalizeEmail(body.email);
  if (body.email !== undefined) {
    if (!nextEmail) throw new Error('INVALID_EMAIL');
    if (nextEmail !== user.email) {
      await ensureEmailUnique(c, nextEmail, user.id);

      const code = randomCode();
      await setCode(c, user.id, {
        codeField: 'emailChangeCode',
        attemptsField: 'emailChangeCodeAttempts',
        expiresField: 'timeEmailChangeCodeExpired',
        code,
        expiresAt: getExpiresAt(CODE_EXPIRES_IN, 30 * 60),
        extra: {
          emailToChange: nextEmail,
        },
      });

      await sendEmailChangeCode(c, nextEmail, user, code);
      emailChangeRequested = true;
    }
  }

  const nextPhone = body.phone === undefined ? null : normalizePhone(body.phone);
  if (body.phone !== undefined) {
    if (!nextPhone) throw new Error('INVALID_PHONE');

    if (nextPhone !== user.phone) {
      await ensurePhoneUnique(c, nextPhone, user.id);

      const code = randomCode();
      await setCode(c, user.id, {
        codeField: 'phoneChangeCode',
        attemptsField: 'phoneChangeCodeAttempts',
        expiresField: 'timePhoneChangeCodeExpired',
        code,
        expiresAt: getExpiresAt(CODE_EXPIRES_IN, 30 * 60),
        extra: {
          phoneToChange: nextPhone,
        },
      });

      await sendPhoneConfirmationCode(c, nextPhone, code);
      phoneChangeRequested = true;
    } else if (user.phone && !user.isPhoneVerified) {
      const code = randomCode();
      await setCode(c, user.id, {
        codeField: 'phoneCode',
        attemptsField: 'phoneCodeAttempts',
        expiresField: 'timePhoneCodeExpired',
        code,
        expiresAt: getExpiresAt(CODE_EXPIRES_IN, 30 * 60),
      });
      await sendPhoneConfirmationCode(c, user.phone, code);
      phoneChangeRequested = true;
    }
  }

  if (Object.keys(updates).length) {
    await dbWrite('users')
      .where({ id: authUser.id })
      .update({
        ...updates,
        timeUpdated: dbWrite.fn.now(),
      });
  }

  c.set('result', {
    ok: true,
    passwordChanged,
    emailChangeRequested,
    phoneChangeRequested,
  });
});

const confirmEmailChange = async (c: AppContext) => {
  const { user, code } = await getConfirmationPayload(c, 'email');

  if (!user.emailToChange) throw new Error('NOTHING_TO_CONFIRM');

  await verifyStoredCode(c, user, {
    code,
    codeField: 'emailChangeCode',
    attemptsField: 'emailChangeCodeAttempts',
    expiresField: 'timeEmailChangeCodeExpired',
  });

  await ensureEmailUnique(c, user.emailToChange, user.id);

  const dbWrite = getDbWrite(c);
  await dbWrite('users')
    .where({ id: user.id })
    .update({
      email: user.emailToChange,
      emailToChange: null,
      emailChangeCode: null,
      emailChangeCodeAttempts: 0,
      timeEmailChangeCodeExpired: null,
      isEmailVerified: true,
      role: getRoleAfterEmailConfirmation(user.role),
      timeUpdated: dbWrite.fn.now(),
    });

  await saveAuthResult(c, {
    ...user,
    role: getRoleAfterEmailConfirmation(user.role),
    email: user.emailToChange,
    emailToChange: null,
    isEmailVerified: true,
  });
};

login.post('/login/email', confirmEmailChange);
login.post('/login/email/confirm', confirmEmailChange);

login.post('/login/email/resend', async (c) => {
  const user = await getCurrentUserRecord(c);

  if (user.emailToChange) {
    const code = randomCode();
    await setCode(c, user.id, {
      codeField: 'emailChangeCode',
      attemptsField: 'emailChangeCodeAttempts',
      expiresField: 'timeEmailChangeCodeExpired',
      code,
      expiresAt: getExpiresAt(CODE_EXPIRES_IN, 30 * 60),
      extra: {
        emailToChange: user.emailToChange,
      },
    });

    await sendEmailChangeCode(c, user.emailToChange, user, code);
    c.set('result', { ok: true });
    return;
  }

  if (!user.email || user.isEmailVerified) {
    throw new Error('NOTHING_TO_CONFIRM');
  }

  const code = randomCode();
  await setCode(c, user.id, {
    codeField: 'registerCode',
    attemptsField: 'registerCodeAttempts',
    expiresField: 'timeRegisterCodeExpired',
    code,
    expiresAt: getExpiresAt(CODE_EXPIRES_IN, 30 * 60),
  });

  await sendRegisterCode(c, user, code);
  c.set('result', { ok: true });
});

const confirmPhone = async (c: AppContext) => {
  const { user, code } = await getConfirmationPayload(c, 'phone');
  const dbWrite = getDbWrite(c);

  if (user.phoneToChange && user.phoneChangeCode) {
    await verifyStoredCode(c, user, {
      code,
      codeField: 'phoneChangeCode',
      attemptsField: 'phoneChangeCodeAttempts',
      expiresField: 'timePhoneChangeCodeExpired',
    });

    await ensurePhoneUnique(c, user.phoneToChange, user.id);

    await dbWrite('users')
      .where({ id: user.id })
      .update({
        phone: user.phoneToChange,
        phoneToChange: null,
        phoneChangeCode: null,
        phoneChangeCodeAttempts: 0,
        timePhoneChangeCodeExpired: null,
        isPhoneVerified: true,
        timeUpdated: dbWrite.fn.now(),
      });

    await saveAuthResult(c, {
      ...user,
      phone: user.phoneToChange,
      phoneToChange: null,
      isPhoneVerified: true,
    });
    return;
  }

  if (!user.phone || !user.phoneCode) {
    throw new Error('NOTHING_TO_CONFIRM');
  }

  await verifyStoredCode(c, user, {
    code,
    codeField: 'phoneCode',
    attemptsField: 'phoneCodeAttempts',
    expiresField: 'timePhoneCodeExpired',
  });

  await clearCode(c, user.id, {
    codeField: 'phoneCode',
    attemptsField: 'phoneCodeAttempts',
    expiresField: 'timePhoneCodeExpired',
    extra: {
      isPhoneVerified: true,
    },
  });

  await saveAuthResult(c, {
    ...user,
    isPhoneVerified: true,
    phoneCode: null,
  });
};

login.post('/login/phone', confirmPhone);
login.post('/login/phone/confirm', confirmPhone);

login.post('/login/phone/resend', async (c) => {
  const user = await getCurrentUserRecord(c);

  if (user.phoneToChange) {
    const code = randomCode();
    await setCode(c, user.id, {
      codeField: 'phoneChangeCode',
      attemptsField: 'phoneChangeCodeAttempts',
      expiresField: 'timePhoneChangeCodeExpired',
      code,
      expiresAt: getExpiresAt(CODE_EXPIRES_IN, 30 * 60),
      extra: {
        phoneToChange: user.phoneToChange,
      },
    });

    await sendPhoneConfirmationCode(c, user.phoneToChange, code);
    c.set('result', { ok: true });
    return;
  }

  if (!user.phone) throw new Error('NOTHING_TO_CONFIRM');

  const code = randomCode();
  await setCode(c, user.id, {
    codeField: 'phoneCode',
    attemptsField: 'phoneCodeAttempts',
    expiresField: 'timePhoneCodeExpired',
    code,
    expiresAt: getExpiresAt(CODE_EXPIRES_IN, 30 * 60),
  });

  await sendPhoneConfirmationCode(c, user.phone, code);
  c.set('result', { ok: true });
});

login.get('/login/me', async (c) => {
  const user = await getCurrentUserRecord(c);
  const result = { ...toPublicAuthUser(user) };
  for (const field of USER_HIDDEN_FIELDS) delete result[field as keyof typeof result];

  c.set('result', {
    ...result,
    email: user.email || null,
    phone: user.phone || null,
    role: user.role || (user.isEmailVerified ? VERIFIED_ROLE : UNVERIFIED_ROLE),
    roles: getUserRoles(user),
    permissionsHint: Object.keys(USER_VISIBLE_FOR),
    ownerPermissionsHint: USER_OWNER_PERMISSIONS,
  });
});

export { login };
