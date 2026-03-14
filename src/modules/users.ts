import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Routings } from 'the-api-routings';
import type { AppContext, CrudBuilderOptionsType } from 'the-api-routings';
import {
  getExpiresAt,
  hashPassword,
  normalizeEmail,
  normalizePhone,
  randomCode,
  randomSalt,
} from '../lib/auth';
import {
  deleteStoredFile,
  getDb,
  getDbWrite,
  hasPermission,
  requireAuth,
  sanitizeUser,
  sendEmail,
  sendSms,
  uploadFile,
  type UserRecord,
} from '../lib/runtime';
import {
  USER_EDITABLE_FOR,
  USER_HIDDEN_FIELDS,
  USER_OWNER_PERMISSIONS,
  USER_VISIBLE_FOR,
} from '../lib/user-config';

const moduleDir = dirname(fileURLToPath(import.meta.url));
const users = new Routings({ migrationDirs: [resolve(moduleDir, '../migrations')] });

const VERIFIED_ROLE = process.env.AUTH_VERIFIED_ROLE || process.env.AUTH_DEFAULT_ROLE || 'registered';
const UNVERIFIED_ROLE = process.env.AUTH_UNVERIFIED_ROLE || 'unverified';
const CODE_EXPIRES_IN = process.env.AUTH_CODE_EXPIRES_IN || '30m';

const USERS_ERRORS = {
  USER_NOT_FOUND: {
    code: 201,
    status: 404,
    description: 'User not found',
  },
  EMAIL_EXISTS: {
    code: 202,
    status: 409,
    description: 'Email already exists',
  },
  PHONE_EXISTS: {
    code: 203,
    status: 409,
    description: 'Phone already exists',
  },
  LOGIN_EXISTS: {
    code: 204,
    status: 409,
    description: 'Login already exists',
  },
  INVALID_EMAIL: {
    code: 205,
    status: 400,
    description: 'Email is invalid',
  },
  INVALID_PHONE: {
    code: 206,
    status: 400,
    description: 'Phone is invalid',
  },
  PASSWORD_REQUIRED: {
    code: 207,
    status: 400,
    description: 'Password is required',
  },
  AVATAR_REQUIRED: {
    code: 208,
    status: 400,
    description: 'Avatar file is required',
  },
} as const;

const getRoleAfterEmailConfirmation = (role: string | null | undefined): string =>
  role === UNVERIFIED_ROLE || !role ? VERIFIED_ROLE : role;

const USERS_READ_ONLY_FIELDS = [
  'id',
  'timeCreated',
  'timeUpdated',
  'timeDeleted',
  'isDeleted',
  'password',
  'salt',
  'refresh',
  'timeRefreshExpired',
  'registerCode',
  'registerCodeAttempts',
  'timeRegisterCodeExpired',
  'recoverCode',
  'recoverCodeAttempts',
  'timeRecoverCodeExpired',
  'phoneCode',
  'phoneCodeAttempts',
  'timePhoneCodeExpired',
  'phoneChangeCode',
  'phoneChangeCodeAttempts',
  'timePhoneChangeCodeExpired',
  'phoneToChange',
  'emailChangeCode',
  'emailChangeCodeAttempts',
  'timeEmailChangeCodeExpired',
  'emailToChange',
  'avatar',
];

const CREATE_BASE_FIELDS = ['email', 'password', 'login', 'phone', 'fullName', 'locale', 'timezone'];
const UPDATE_BASE_FIELDS = ['fullName', 'locale', 'timezone'];

const trimString = (value: unknown): string | null => {
  if (typeof value !== 'string') return null;
  const result = value.trim();
  return result || null;
};

const usersCrudConfig: CrudBuilderOptionsType = {
  table: 'users',
  userIdFieldName: 'id',
  permissions: {
    methods: ['GET', 'POST', 'PATCH', 'DELETE'] as ('GET' | 'POST' | 'PATCH' | 'DELETE')[],
    owner: USER_OWNER_PERMISSIONS,
  },
  validation: {
    body: {
      post: {
        email: { type: 'string', required: true },
        password: { type: 'string', required: true },
        login: { type: 'string' },
        phone: { type: 'string' },
        fullName: { type: 'string' },
        locale: { type: 'string' },
        timezone: { type: 'string' },
      },
      patch: {
        email: { type: 'string' },
        phone: { type: 'string' },
        fullName: { type: 'string' },
        locale: { type: 'string' },
        timezone: { type: 'string' },
        role: { type: 'string' },
        isBlocked: { type: 'boolean' },
        isDeleted: { type: 'boolean' },
        isEmailInvalid: { type: 'boolean' },
        isPhoneInvalid: { type: 'boolean' },
        isEmailVerified: { type: 'boolean' },
        isPhoneVerified: { type: 'boolean' },
      },
    },
  },
  fieldRules: {
    hidden: USER_HIDDEN_FIELDS,
    readOnly: USERS_READ_ONLY_FIELDS,
    visibleFor: USER_VISIBLE_FOR,
    editableFor: USER_EDITABLE_FOR,
  },
};

const sanitizeUserResult = (c: AppContext, user: UserRecord): Record<string, unknown> =>
  sanitizeUser({
    c,
    user,
    hiddenFields: USER_HIDDEN_FIELDS,
    visibleFor: USER_VISIBLE_FOR,
    ownerPermissions: USER_OWNER_PERMISSIONS,
  });

const getUserById = async (c: AppContext, id: number): Promise<UserRecord> => {
  const db = getDb(c);
  const user = await db('users').where({ id }).first() as UserRecord | undefined;
  if (!user || user.isDeleted) throw new Error('USER_NOT_FOUND');
  return user;
};

const ensureEmailUnique = async (c: AppContext, email: string, exceptId?: number): Promise<void> => {
  const db = getDb(c);
  const query = db('users').whereRaw('LOWER(email) = ?', [email]);
  if (exceptId) query.whereNot({ id: exceptId });
  const existing = await query.first();
  if (existing) throw new Error('EMAIL_EXISTS');
};

const ensurePhoneUnique = async (c: AppContext, phone: string, exceptId?: number): Promise<void> => {
  const db = getDb(c);
  const query = db('users').where({ phone });
  if (exceptId) query.whereNot({ id: exceptId });
  const existing = await query.first();
  if (existing) throw new Error('PHONE_EXISTS');
};

const ensureLoginUnique = async (c: AppContext, loginName: string, exceptId?: number): Promise<void> => {
  const db = getDb(c);
  const query = db('users').whereRaw('LOWER(login) = ?', [loginName.toLowerCase()]);
  if (exceptId) query.whereNot({ id: exceptId });
  const existing = await query.first();
  if (existing) throw new Error('LOGIN_EXISTS');
};

const getEditableFields = (c: AppContext, baseFields: string[]): Set<string> => {
  const editable = new Set(baseFields);

  for (const [permission, fields] of Object.entries(USER_EDITABLE_FOR)) {
    if (hasPermission(c, permission)) {
      for (const field of fields) editable.add(field);
    }
  }

  return editable;
};

const assertRoutePermission = (c: AppContext, permission: string): void => {
  if (!hasPermission(c, permission)) throw new Error('ACCESS_DENIED');
};

const sendEmailVerification = async (c: AppContext, email: string, code: string): Promise<void> => {
  await sendEmail(c, {
    to: email,
    subject: 'Confirm your email',
    text: `Use this code to confirm your email: ${code}`,
  });
};

const sendPhoneVerification = async (c: AppContext, phone: string, code: string): Promise<void> => {
  await sendSms(c, {
    to: phone,
    body: `Your confirmation code is ${code}`,
  });
};

const parseUserId = (c: AppContext): number => {
  const rawId = c.req.param('id')
    || c.req.param().id
    || c.req.path.split('/').filter(Boolean).at(-1)
    || '';
  const id = Number(rawId);
  if (!Number.isInteger(id) || id < 1) throw new Error('USER_NOT_FOUND');
  return id;
};

users.errors(USERS_ERRORS);

users.post('/users', async (c) => {
  requireAuth(c);
  assertRoutePermission(c, 'users.post');

  const body = await c.req.json<Record<string, unknown>>();
  const requestedFields = Object.keys(body);
  const editableFields = getEditableFields(c, CREATE_BASE_FIELDS);
  const deniedFields = requestedFields.filter((field) => !editableFields.has(field));
  if (deniedFields.length) throw new Error('ACCESS_DENIED');

  const email = normalizeEmail(body.email);
  const password = trimString(body.password);
  const phone = body.phone === undefined || body.phone === null ? null : normalizePhone(body.phone);
  const loginName = trimString(body.login);

  if (!email) throw new Error('INVALID_EMAIL');
  if (!password) throw new Error('PASSWORD_REQUIRED');
  if (body.phone !== undefined && body.phone !== null && !phone) throw new Error('INVALID_PHONE');

  await ensureEmailUnique(c, email);
  if (phone) await ensurePhoneUnique(c, phone);
  if (loginName) await ensureLoginUnique(c, loginName);

  const dbWrite = getDbWrite(c);
  const salt = randomSalt();
  const passwordHash = hashPassword(password, salt);
  const emailVerificationCode = body.isEmailVerified === true ? null : randomCode();
  const phoneVerificationCode =
    phone && body.isPhoneVerified !== true ? randomCode() : null;

  const payload: Record<string, unknown> = {
    email,
    password: passwordHash,
    salt,
    fullName: trimString(body.fullName),
    login: loginName,
    phone,
    locale: trimString(body.locale),
    timezone: trimString(body.timezone),
    role: trimString(body.role) || (body.isEmailVerified === true ? VERIFIED_ROLE : UNVERIFIED_ROLE),
    isBlocked: body.isBlocked === true,
    isDeleted: body.isDeleted === true,
    isEmailInvalid: body.isEmailInvalid === true,
    isPhoneInvalid: body.isPhoneInvalid === true,
    isEmailVerified: body.isEmailVerified === true,
    isPhoneVerified: body.isPhoneVerified === true || !phone,
    timePasswordChanged: dbWrite.fn.now(),
    registerCode: emailVerificationCode,
    registerCodeAttempts: 0,
    timeRegisterCodeExpired: emailVerificationCode ? getExpiresAt(CODE_EXPIRES_IN, 30 * 60) : null,
    phoneCode: phoneVerificationCode,
    phoneCodeAttempts: 0,
    timePhoneCodeExpired: phoneVerificationCode ? getExpiresAt(CODE_EXPIRES_IN, 30 * 60) : null,
  };

  const [user] = await dbWrite('users').insert(payload).returning('*') as UserRecord[];

  if (emailVerificationCode) await sendEmailVerification(c, email, emailVerificationCode);
  if (phone && phoneVerificationCode) await sendPhoneVerification(c, phone, phoneVerificationCode);

  c.set('result', sanitizeUserResult(c, user));
});

users.patch('/users/:id', async (c) => {
  requireAuth(c);
  assertRoutePermission(c, 'users.patch');

  const id = parseUserId(c);
  const body = await c.req.json<Record<string, unknown>>();
  const requestedFields = Object.keys(body);
  const editableFields = getEditableFields(c, UPDATE_BASE_FIELDS);
  const deniedFields = requestedFields.filter((field) => !editableFields.has(field));
  if (deniedFields.length) throw new Error('ACCESS_DENIED');

  const user = await getUserById(c, id);
  const dbWrite = getDbWrite(c);
  const updates: Record<string, unknown> = {};

  if (body.fullName !== undefined) updates.fullName = trimString(body.fullName);
  if (body.locale !== undefined) updates.locale = trimString(body.locale);
  if (body.timezone !== undefined) updates.timezone = trimString(body.timezone);
  if (body.role !== undefined) updates.role = trimString(body.role) || VERIFIED_ROLE;
  if (body.isBlocked !== undefined) updates.isBlocked = body.isBlocked === true;
  if (body.isDeleted !== undefined) updates.isDeleted = body.isDeleted === true;
  if (body.isEmailInvalid !== undefined) updates.isEmailInvalid = body.isEmailInvalid === true;
  if (body.isPhoneInvalid !== undefined) updates.isPhoneInvalid = body.isPhoneInvalid === true;
  if (body.isEmailVerified !== undefined) updates.isEmailVerified = body.isEmailVerified === true;
  if (body.isEmailVerified === true && body.role === undefined) {
    updates.role = getRoleAfterEmailConfirmation(user.role);
  }
  if (body.isPhoneVerified !== undefined) updates.isPhoneVerified = body.isPhoneVerified === true;

  if (body.email !== undefined) {
    const email = normalizeEmail(body.email);
    if (!email) throw new Error('INVALID_EMAIL');
    if (email !== user.email) {
      await ensureEmailUnique(c, email, user.id);
      const code = body.isEmailVerified === true ? null : randomCode();

      updates.email = email;
      updates.emailToChange = null;
      updates.emailChangeCode = null;
      updates.emailChangeCodeAttempts = 0;
      updates.timeEmailChangeCodeExpired = null;
      updates.isEmailVerified = body.isEmailVerified === true;
      if (body.isEmailVerified === true) {
        updates.role = getRoleAfterEmailConfirmation(user.role);
      }
      updates.registerCode = code;
      updates.registerCodeAttempts = 0;
      updates.timeRegisterCodeExpired = code ? getExpiresAt(CODE_EXPIRES_IN, 30 * 60) : null;

      if (code) await sendEmailVerification(c, email, code);
    }
  }

  if (body.phone !== undefined) {
    if (body.phone === null || body.phone === '') {
      updates.phone = null;
      updates.phoneToChange = null;
      updates.phoneCode = null;
      updates.phoneCodeAttempts = 0;
      updates.timePhoneCodeExpired = null;
      updates.phoneChangeCode = null;
      updates.phoneChangeCodeAttempts = 0;
      updates.timePhoneChangeCodeExpired = null;
      updates.isPhoneVerified = false;
    } else {
      const phone = normalizePhone(body.phone);
      if (!phone) throw new Error('INVALID_PHONE');

      if (phone !== user.phone) {
        await ensurePhoneUnique(c, phone, user.id);
        const code = body.isPhoneVerified === true ? null : randomCode();

        updates.phone = phone;
        updates.phoneToChange = null;
        updates.phoneChangeCode = null;
        updates.phoneChangeCodeAttempts = 0;
        updates.timePhoneChangeCodeExpired = null;
        updates.isPhoneVerified = body.isPhoneVerified === true;
        updates.phoneCode = code;
        updates.phoneCodeAttempts = 0;
        updates.timePhoneCodeExpired = code ? getExpiresAt(CODE_EXPIRES_IN, 30 * 60) : null;

        if (code) await sendPhoneVerification(c, phone, code);
      }
    }
  }

  if (body.isDeleted === true) {
    updates.timeDeleted = dbWrite.fn.now();
  } else if (body.isDeleted === false) {
    updates.timeDeleted = null;
  }

  if (Object.keys(updates).length) {
    await dbWrite('users')
      .where({ id })
      .update({
        ...updates,
        timeUpdated: dbWrite.fn.now(),
      });
  }

  const updated = await getUserById(c, id);
  c.set('result', sanitizeUserResult(c, updated));
});

users.delete('/users/:id', async (c) => {
  requireAuth(c);
  assertRoutePermission(c, 'users.delete');

  const id = parseUserId(c);
  await getUserById(c, id);

  const dbWrite = getDbWrite(c);
  await dbWrite('users')
    .where({ id })
    .update({
      isDeleted: true,
      timeDeleted: dbWrite.fn.now(),
      refresh: null,
      timeRefreshExpired: null,
      timeUpdated: dbWrite.fn.now(),
    });

  c.set('result', { ok: true });
});

users.post('/users/:id/avatar', async (c) => {
  const authUser = requireAuth(c);
  const id = parseUserId(c);
  const isOwner = `${authUser.id}` === `${id}`;
  const canUpload = isOwner || hasPermission(c, 'users.patch') || hasPermission(c, 'users.uploadAvatar');
  if (!canUpload) throw new Error('ACCESS_DENIED');

  const user = await getUserById(c, id);
  const body = await c.req.parseBody();
  const avatar = body.avatar as File | undefined;
  if (!(avatar instanceof File)) throw new Error('AVATAR_REQUIRED');

  const stored = await uploadFile(c, avatar, `users/${id}/avatar`);
  await deleteStoredFile(c, user.avatar || null);

  const dbWrite = getDbWrite(c);
  await dbWrite('users')
    .where({ id })
    .update({
      avatar: stored.path,
      timeUpdated: dbWrite.fn.now(),
    });

  const updated = await getUserById(c, id);
  c.set('result', sanitizeUserResult(c, updated));
});

users.delete('/users/:id/avatar', async (c) => {
  const authUser = requireAuth(c);
  const id = parseUserId(c);
  const isOwner = `${authUser.id}` === `${id}`;
  const canUpload = isOwner || hasPermission(c, 'users.patch') || hasPermission(c, 'users.uploadAvatar');
  if (!canUpload) throw new Error('ACCESS_DENIED');

  const user = await getUserById(c, id);
  await deleteStoredFile(c, user.avatar || null);

  const dbWrite = getDbWrite(c);
  await dbWrite('users')
    .where({ id })
    .update({
      avatar: null,
      timeUpdated: dbWrite.fn.now(),
    });

  const updated = await getUserById(c, id);
  c.set('result', sanitizeUserResult(c, updated));
});

users.crud(usersCrudConfig);

export { users };
