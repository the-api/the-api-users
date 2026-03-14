import { mkdir, unlink, writeFile } from 'node:fs/promises';
import { basename, dirname, extname, join, posix } from 'node:path';
import type { Knex } from 'knex';
import type { AppContext, RolesService } from 'the-api-routings';
import { randomToken } from './auth';

export type AuthUser = {
  id?: number | string;
  role?: string | null;
  roles?: string[];
  [key: string]: unknown;
};

export type UserRecord = {
  id: number;
  timeCreated?: Date | string | null;
  timeUpdated?: Date | string | null;
  timeDeleted?: Date | string | null;
  isBlocked?: boolean;
  isDeleted?: boolean;
  login?: string | null;
  password?: string | null;
  salt?: string | null;
  timePasswordChanged?: Date | string | null;
  email?: string | null;
  isEmailVerified?: boolean;
  isEmailInvalid?: boolean;
  phone?: string | null;
  isPhoneVerified?: boolean;
  isPhoneInvalid?: boolean;
  fullName?: string | null;
  avatar?: string | null;
  role?: string | null;
  locale?: string | null;
  timezone?: string | null;
  refresh?: string | null;
  timeRefreshExpired?: Date | string | null;
  registerCode?: string | null;
  registerCodeAttempts?: number;
  timeRegisterCodeExpired?: Date | string | null;
  recoverCode?: string | null;
  recoverCodeAttempts?: number;
  timeRecoverCodeExpired?: Date | string | null;
  phoneCode?: string | null;
  phoneCodeAttempts?: number;
  timePhoneCodeExpired?: Date | string | null;
  phoneToChange?: string | null;
  phoneChangeCode?: string | null;
  phoneChangeCodeAttempts?: number;
  timePhoneChangeCodeExpired?: Date | string | null;
  emailToChange?: string | null;
  emailChangeCode?: string | null;
  emailChangeCodeAttempts?: number;
  timeEmailChangeCodeExpired?: Date | string | null;
  oauthProviders?: Record<string, unknown> | null;
  [key: string]: unknown;
};

export type VisibilityMap = Record<string, string[]>;

type EmailSender = (params: {
  to: string;
  template?: string;
  subject?: string;
  text?: string;
  html?: string;
  data?: Record<string, unknown>;
}) => Promise<void>;

type FileService = {
  upload?: (file: File, destDir: string) => Promise<{ path: string; name: string; size: number }>;
  delete?: (path: string) => Promise<void>;
};

const FILES_FOLDER = process.env.FILES_FOLDER || '';
const VERIFIED_ROLE = process.env.AUTH_VERIFIED_ROLE || process.env.AUTH_DEFAULT_ROLE || 'registered';
const UNVERIFIED_ROLE = process.env.AUTH_UNVERIFIED_ROLE || 'unverified';

const getRolesService = (c: AppContext): RolesService | undefined =>
  (c.var.roles || c.env.roles) as RolesService | undefined;

export const getDb = (c: AppContext): Knex => {
  const db = (c.var.db || c.env.db) as Knex | undefined;
  if (!db) throw new Error('DB_CONNECTION_REQUIRED');
  return db;
};

export const getDbWrite = (c: AppContext): Knex => {
  const db = ((c.var.dbWrite || c.env.dbWrite || c.var.db || c.env.db) as Knex | undefined);
  if (!db) throw new Error('DB_WRITE_CONNECTION_REQUIRED');
  return db;
};

export const getRequestUser = (c: AppContext): AuthUser =>
  ((c.var.user || {}) as AuthUser);

export const requireAuth = (c: AppContext): AuthUser => {
  const user = getRequestUser(c);

  if (!user.id || !Array.isArray(user.roles) || user.roles.includes('guest')) {
    throw new Error('NO_TOKEN');
  }

  return user;
};

export const isUserIdentityVerified = (
  user: Partial<UserRecord> | AuthUser | null | undefined,
): boolean => {
  if (!user) return false;
  if (user.isEmailVerified && !!user.email) return true;
  if (user.isPhoneVerified && !!user.phone) return true;
  return !!user.role && String(user.role) !== UNVERIFIED_ROLE;
};

export const getUserRoles = (user: Partial<UserRecord> | AuthUser | null | undefined): string[] => {
  const roles = Array.isArray(user?.roles)
    ? user?.roles
    : user?.role
      ? [String(user.role)]
      : [isUserIdentityVerified(user) ? VERIFIED_ROLE : UNVERIFIED_ROLE];

  return Array.from(new Set(roles.filter(Boolean).map(String)));
};

export const hasPermission = (
  c: AppContext,
  permission: string,
  roles: string[] = getUserRoles(getRequestUser(c)),
): boolean => {
  const service = getRolesService(c);
  if (!service) return true;

  const permissions = service.getPermissions(roles);
  return service.checkWildcardPermissions({ key: permission, permissions });
};

export const sanitizeUser = ({
  c,
  user,
  hiddenFields,
  visibleFor = {},
  ownerPermissions = [],
}: {
  c: AppContext;
  user: UserRecord;
  hiddenFields: string[];
  visibleFor?: VisibilityMap;
  ownerPermissions?: string[];
}): Record<string, unknown> => {
  const requestUser = getRequestUser(c);
  const service = getRolesService(c);
  const result = { ...user } as Record<string, unknown>;
  const hidden = new Set(hiddenFields);

  if (!service) {
    for (const field of hidden) delete result[field];
    return result;
  }

  const permissions = service.getPermissions(getUserRoles(requestUser));
  const ownerPermissionMap = service.getPermissions(ownerPermissions);
  const isOwner = !!requestUser.id && `${requestUser.id}` === `${user.id}`;

  for (const [permission, fields] of Object.entries(visibleFor)) {
    const canSee = service.checkWildcardPermissions({
      key: permission,
      permissions: isOwner ? { ...permissions, ...ownerPermissionMap } : permissions,
    });

    if (canSee) {
      for (const field of fields) hidden.delete(field);
    }
  }

  for (const field of hidden) delete result[field];
  return result;
};

export const sendEmail = async (
  c: AppContext,
  params: {
    to: string;
    template?: string;
    subject?: string;
    text?: string;
    html?: string;
    data?: Record<string, unknown>;
  },
): Promise<void> => {
  const email = c.var.email as EmailSender | undefined;
  if (email) {
    await email(params);
    return;
  }

  c.var.log?.('Email delivery skipped, no email middleware configured', params);
};

export const sendSms = async (
  c: AppContext,
  {
    to,
    body,
  }: {
    to: string;
    body: string;
  },
): Promise<void> => {
  const {
    SMS_PROVIDER,
    TWILIO_ACCOUNT_SID,
    TWILIO_AUTH_TOKEN,
    TWILIO_FROM,
  } = process.env;

  if (
    (SMS_PROVIDER === 'twilio' || (!SMS_PROVIDER && TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN && TWILIO_FROM))
    && TWILIO_ACCOUNT_SID
    && TWILIO_AUTH_TOKEN
    && TWILIO_FROM
  ) {
    const endpoint = `https://api.twilio.com/2010-04-01/Accounts/${TWILIO_ACCOUNT_SID}/Messages.json`;
    const form = new URLSearchParams({ To: to, From: TWILIO_FROM, Body: body });
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        Authorization: `Basic ${Buffer.from(`${TWILIO_ACCOUNT_SID}:${TWILIO_AUTH_TOKEN}`).toString('base64')}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: form,
    });

    if (!response.ok) {
      const errorText = await response.text();
      c.var.log?.('SMS delivery failed', errorText);
      throw new Error('SMS_SEND_FAILED');
    }

    return;
  }

  c.var.log?.('SMS delivery skipped, no SMS provider configured', { to, body });
};

const createStoredFile = async (file: File, destDir: string): Promise<{ path: string; name: string; size: number }> => {
  if (!FILES_FOLDER) throw new Error('FILES_NO_STORAGE_CONFIGURED');

  const extension = extname(file.name) || '';
  const fileName = `${randomToken(12)}${extension}`;
  const relativePath = posix.join(destDir.replace(/\\/g, '/'), fileName);
  const fullPath = join(FILES_FOLDER, relativePath);

  await mkdir(dirname(fullPath), { recursive: true });
  await writeFile(fullPath, Buffer.from(await file.arrayBuffer()));

  return { path: relativePath, name: fileName, size: file.size };
};

export const uploadFile = async (
  c: AppContext,
  file: File,
  destDir: string,
): Promise<{ path: string; name: string; size: number }> => {
  const files = c.var.files as FileService | undefined;
  if (files?.upload) return files.upload(file, destDir);
  return createStoredFile(file, destDir);
};

export const deleteStoredFile = async (c: AppContext, filePath: string | null | undefined): Promise<void> => {
  if (!filePath) return;

  const files = c.var.files as FileService | undefined;
  if (files?.delete) {
    await files.delete(filePath);
    return;
  }

  if (!FILES_FOLDER) return;

  const fullPath = join(FILES_FOLDER, filePath);
  try {
    await unlink(fullPath);
  } catch {
    c.var.log?.('Avatar cleanup skipped', basename(filePath));
  }
};
