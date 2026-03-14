import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';
import type { AppContext } from 'the-api-routings';
import { getCookie, setCookie } from 'hono/cookie';
import { normalizeEmail, normalizePhone, randomToken } from './auth';
import { getDb, type UserRecord } from './runtime';

export const OAUTH_SERVICES = ['apple', 'facebook', 'github', 'google', 'linkedin', 'microsoft', 'twitter'] as const;

export type OAuthServiceName = typeof OAUTH_SERVICES[number];

export type OAuthIdentity = {
  service: OAuthServiceName;
  externalId: string;
  email?: string | null;
  emailVerified?: boolean;
  phone?: string | null;
  phoneVerified?: boolean;
  fullName?: string | null;
  givenName?: string | null;
  familyName?: string | null;
  username?: string | null;
  avatar?: string | null;
  locale?: string | null;
  grantedScopes?: string[];
  accessToken?: string | null;
  accessTokenExpiresIn?: number | null;
  refreshToken?: string | null;
  refreshTokenExpiresIn?: number | null;
  rawProfile: Record<string, unknown>;
};

export type OAuthProviderRecord = {
  service: OAuthServiceName;
  externalId: string;
  email: string | null;
  emailVerified: boolean;
  phone: string | null;
  phoneVerified: boolean;
  fullName: string | null;
  givenName: string | null;
  familyName: string | null;
  username: string | null;
  avatar: string | null;
  locale: string | null;
  grantedScopes: string[];
  linkedAt: string;
  updatedAt: string;
  profile: Record<string, unknown>;
};

export type OAuthProvidersMap = Partial<Record<OAuthServiceName, OAuthProviderRecord>>;

type OAuthExchangePayload = {
  code?: string | null;
  accessToken?: string | null;
  idToken?: string | null;
  redirectUri?: string | null;
  codeVerifier?: string | null;
  user?: unknown;
};

type OAuthServiceConfig = {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scope: string[];
  fields?: string[];
  tenantId?: string;
};

const APPLE_AUDIENCE = 'https://appleid.apple.com';
const FACEBOOK_API_VERSION = 'v18.0';
const GITHUB_API_VERSION = '2022-11-28';
const MICROSOFT_TENANT = 'common';

const getString = (value: unknown): string | null => {
  if (typeof value === 'number' || typeof value === 'bigint') return String(value);
  if (typeof value !== 'string') return null;
  const result = value.trim();
  return result || null;
};

const splitScopes = (value: string | undefined, fallback: string[]): string[] => {
  const input = getString(value);
  if (!input) return fallback;

  return Array.from(new Set(
    input
      .split(/[,\s]+/)
      .map((item) => item.trim())
      .filter(Boolean),
  ));
};

const getEnv = (...keys: string[]): string | null => {
  for (const key of keys) {
    const value = getString(process.env[key]);
    if (value) return value;
  }

  return null;
};

const getOAuthStateCookieName = (service: OAuthServiceName): string => `oauth_state_${service}`;

const getOAuthTempCookieName = (
  service: OAuthServiceName,
  key: 'code_verifier',
): string => `oauth_${key}_${service}`;

const setOAuthStateCookie = (c: AppContext, service: OAuthServiceName, state: string): void => {
  setCookie(c, getOAuthStateCookieName(service), state, {
    httpOnly: true,
    path: '/',
    sameSite: 'Lax',
    secure: c.req.url.startsWith('https://'),
    maxAge: 10 * 60,
  });
};

const setOAuthTempCookie = (
  c: AppContext,
  service: OAuthServiceName,
  key: 'code_verifier',
  value: string,
): void => {
  setCookie(c, getOAuthTempCookieName(service, key), value, {
    httpOnly: true,
    path: '/',
    sameSite: 'Lax',
    secure: c.req.url.startsWith('https://'),
    maxAge: 10 * 60,
  });
};

export const createOAuthState = (): string => randomToken(18);

const toBase64Url = (value: Buffer): string =>
  value
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');

const createCodeVerifier = (): string => randomToken(48);

const createCodeChallenge = (codeVerifier: string): string =>
  toBase64Url(createHash('sha256').update(codeVerifier).digest());

const fromBase64Url = (value: string): Buffer => {
  const normalized = value
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(Math.ceil(value.length / 4) * 4, '=');

  return Buffer.from(normalized, 'base64');
};

const parseJson = <T = Record<string, unknown>>(value: string | null | undefined): T | null => {
  const input = getString(value);
  if (!input) return null;

  try {
    return JSON.parse(input) as T;
  } catch {
    return null;
  }
};

const decodeJwt = (token: string): {
  header: Record<string, any>;
  payload: Record<string, any>;
  signingInput: string;
  signature: Buffer;
} => {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('OAUTH_INVALID_TOKEN');

  const [headerPart, payloadPart, signaturePart] = parts;
  const header = parseJson(fromBase64Url(headerPart).toString('utf8'));
  const payload = parseJson(fromBase64Url(payloadPart).toString('utf8'));
  if (!header || !payload) throw new Error('OAUTH_INVALID_TOKEN');

  return {
    header,
    payload,
    signingInput: `${headerPart}.${payloadPart}`,
    signature: fromBase64Url(signaturePart),
  };
};

export const validateOAuthState = (
  c: AppContext,
  service: OAuthServiceName,
  state: string | null | undefined,
): boolean => {
  const cookieName = getOAuthStateCookieName(service);
  const expected = getCookie(c, cookieName);

  if (!expected) return true;
  if (!state) return false;

  const isValid = expected === state;
  if (isValid) {
    setCookie(c, cookieName, '', {
      httpOnly: true,
      path: '/',
      sameSite: 'Lax',
      secure: c.req.url.startsWith('https://'),
      maxAge: 0,
    });
  }

  return isValid;
};

const getGoogleConfig = (): OAuthServiceConfig => {
  const clientId = getEnv('AUTH_GOOGLE_CLIENT_ID', 'GOOGLE_ID');
  const clientSecret = getEnv('AUTH_GOOGLE_CLIENT_SECRET', 'GOOGLE_SECRET');
  const redirectUri = getEnv('AUTH_GOOGLE_REDIRECT_URI', 'AUTH_GOOGLE_CALLBACK_URL');

  if (!clientId || !clientSecret || !redirectUri) throw new Error('OAUTH_CONFIG_NOT_FOUND');

  return {
    clientId,
    clientSecret,
    redirectUri,
    scope: splitScopes(process.env.AUTH_GOOGLE_SCOPE, ['openid', 'email', 'profile']),
  };
};

const getGithubConfig = (): OAuthServiceConfig => {
  const clientId = getEnv('AUTH_GITHUB_CLIENT_ID', 'GITHUB_ID');
  const clientSecret = getEnv('AUTH_GITHUB_CLIENT_SECRET', 'GITHUB_SECRET');
  const redirectUri = getEnv('AUTH_GITHUB_REDIRECT_URI', 'AUTH_GITHUB_CALLBACK_URL');

  if (!clientId || !clientSecret || !redirectUri) throw new Error('OAUTH_CONFIG_NOT_FOUND');

  return {
    clientId,
    clientSecret,
    redirectUri,
    scope: splitScopes(process.env.AUTH_GITHUB_SCOPE, ['read:user', 'user:email']),
  };
};

const getFacebookConfig = (): OAuthServiceConfig => {
  const clientId = getEnv('AUTH_FACEBOOK_CLIENT_ID', 'FACEBOOK_ID');
  const clientSecret = getEnv('AUTH_FACEBOOK_CLIENT_SECRET', 'FACEBOOK_SECRET');
  const redirectUri = getEnv('AUTH_FACEBOOK_REDIRECT_URI', 'AUTH_FACEBOOK_CALLBACK_URL');

  if (!clientId || !clientSecret || !redirectUri) throw new Error('OAUTH_CONFIG_NOT_FOUND');

  return {
    clientId,
    clientSecret,
    redirectUri,
    scope: splitScopes(process.env.AUTH_FACEBOOK_SCOPE, ['email', 'public_profile']),
    fields: splitScopes(
      process.env.AUTH_FACEBOOK_FIELDS,
      ['id', 'email', 'first_name', 'last_name', 'name', 'picture'],
    ),
  };
};

const getLinkedinConfig = (): OAuthServiceConfig => {
  const clientId = getEnv('AUTH_LINKEDIN_CLIENT_ID', 'LINKEDIN_ID');
  const clientSecret = getEnv('AUTH_LINKEDIN_CLIENT_SECRET', 'LINKEDIN_SECRET');
  const redirectUri = getEnv('AUTH_LINKEDIN_REDIRECT_URI', 'AUTH_LINKEDIN_CALLBACK_URL');

  if (!clientId || !clientSecret || !redirectUri) throw new Error('OAUTH_CONFIG_NOT_FOUND');

  return {
    clientId,
    clientSecret,
    redirectUri,
    scope: splitScopes(process.env.AUTH_LINKEDIN_SCOPE, ['openid', 'profile', 'email']),
  };
};

const getTwitterConfig = (): OAuthServiceConfig => {
  const clientId = getEnv('AUTH_TWITTER_CLIENT_ID', 'AUTH_X_CLIENT_ID', 'X_ID');
  const clientSecret = getEnv('AUTH_TWITTER_CLIENT_SECRET', 'AUTH_X_CLIENT_SECRET', 'X_SECRET');
  const redirectUri = getEnv(
    'AUTH_TWITTER_REDIRECT_URI',
    'AUTH_TWITTER_CALLBACK_URL',
    'AUTH_X_REDIRECT_URI',
    'AUTH_X_CALLBACK_URL',
  );

  if (!clientId || !clientSecret || !redirectUri) throw new Error('OAUTH_CONFIG_NOT_FOUND');

  return {
    clientId,
    clientSecret,
    redirectUri,
    scope: splitScopes(
      process.env.AUTH_TWITTER_SCOPE || process.env.AUTH_X_SCOPE,
      ['tweet.read', 'users.read', 'offline.access'],
    ),
    fields: splitScopes(
      process.env.AUTH_TWITTER_FIELDS || process.env.AUTH_X_FIELDS,
      ['id', 'name', 'username', 'profile_image_url'],
    ),
  };
};

const getMicrosoftConfig = (): OAuthServiceConfig => {
  const clientId = getEnv('AUTH_MICROSOFT_CLIENT_ID', 'AUTH_MSENTRA_CLIENT_ID', 'MSENTRA_ID');
  const clientSecret = getEnv('AUTH_MICROSOFT_CLIENT_SECRET', 'AUTH_MSENTRA_CLIENT_SECRET', 'MSENTRA_SECRET');
  const redirectUri = getEnv(
    'AUTH_MICROSOFT_REDIRECT_URI',
    'AUTH_MICROSOFT_CALLBACK_URL',
    'AUTH_MSENTRA_REDIRECT_URI',
    'AUTH_MSENTRA_CALLBACK_URL',
  );
  const tenantId = getEnv('AUTH_MICROSOFT_TENANT_ID', 'AUTH_MSENTRA_TENANT_ID') || MICROSOFT_TENANT;

  if (!clientId || !clientSecret || !redirectUri) throw new Error('OAUTH_CONFIG_NOT_FOUND');

  return {
    clientId,
    clientSecret,
    redirectUri,
    tenantId,
    scope: splitScopes(
      process.env.AUTH_MICROSOFT_SCOPE || process.env.AUTH_MSENTRA_SCOPE,
      ['openid', 'profile', 'email', 'offline_access', 'User.Read'],
    ),
  };
};

const getApplePrivateKey = (): string | null => {
  const privateKey = getString(process.env.AUTH_APPLE_PRIVATE_KEY);
  if (!privateKey) return null;
  return privateKey.replace(/\\n/g, '\n');
};

const createAppleClientSecret = (): string => {
  const clientId = getEnv('AUTH_APPLE_CLIENT_ID');
  const teamId = getEnv('AUTH_APPLE_TEAM_ID');
  const keyId = getEnv('AUTH_APPLE_KEY_ID');
  const privateKey = getApplePrivateKey();

  if (!clientId || !teamId || !keyId || !privateKey) {
    throw new Error('OAUTH_CONFIG_NOT_FOUND');
  }

  const now = Math.floor(Date.now() / 1000);
  const header = {
    alg: 'ES256',
    kid: keyId,
    typ: 'JWT',
  };
  const payload = {
    iss: teamId,
    iat: now,
    exp: now + (60 * 60 * 24 * 180),
    aud: APPLE_AUDIENCE,
    sub: clientId,
  };
  const encodedHeader = toBase64Url(Buffer.from(JSON.stringify(header)));
  const encodedPayload = toBase64Url(Buffer.from(JSON.stringify(payload)));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = cryptoSign('sha256', Buffer.from(signingInput), {
    key: createPrivateKey(privateKey),
    dsaEncoding: 'ieee-p1363',
  });

  return `${signingInput}.${toBase64Url(signature)}`;
};

const getAppleConfig = (): OAuthServiceConfig => {
  const clientId = getEnv('AUTH_APPLE_CLIENT_ID');
  const redirectUri = getEnv('AUTH_APPLE_REDIRECT_URI', 'AUTH_APPLE_CALLBACK_URL');
  const clientSecret = getEnv('AUTH_APPLE_CLIENT_SECRET') || createAppleClientSecret();

  if (!clientId || !clientSecret || !redirectUri) throw new Error('OAUTH_CONFIG_NOT_FOUND');

  return {
    clientId,
    clientSecret,
    redirectUri,
    scope: splitScopes(process.env.AUTH_APPLE_SCOPE, ['name', 'email']),
  };
};

const getServiceConfig = (service: OAuthServiceName): OAuthServiceConfig => {
  if (service === 'apple') return getAppleConfig();
  if (service === 'google') return getGoogleConfig();
  if (service === 'github') return getGithubConfig();
  if (service === 'facebook') return getFacebookConfig();
  if (service === 'linkedin') return getLinkedinConfig();
  if (service === 'microsoft') return getMicrosoftConfig();
  return getTwitterConfig();
};

const ensureService = (service: string): OAuthServiceName => {
  if ((OAUTH_SERVICES as readonly string[]).includes(service)) {
    return service as OAuthServiceName;
  }

  throw new Error('OAUTH_SERVICE_NOT_SUPPORTED');
};

const toQueryString = (params: Record<string, string | undefined | null>): string => {
  const search = new URLSearchParams();

  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') {
      search.set(key, value);
    }
  }

  return search.toString();
};

const fetchJson = async (
  url: string,
  init?: RequestInit,
): Promise<{ data: any; response: Response }> => {
  const response = await fetch(url, init);
  const text = await response.text();
  let data: any = {};

  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      throw new Error('OAUTH_INVALID_TOKEN');
    }
  }

  if (!response.ok) {
    throw new Error('OAUTH_INVALID_TOKEN');
  }

  return { data, response };
};

const verifyGoogleIdToken = async (idToken: string): Promise<OAuthIdentity> => {
  const { data } = await fetchJson(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(idToken)}`);
  const config = getGoogleConfig();

  if (data?.aud && data.aud !== config.clientId) {
    throw new Error('OAUTH_INVALID_TOKEN');
  }

  const externalId = getString(data?.sub);
  if (!externalId) throw new Error('OAUTH_INVALID_TOKEN');

  return {
    service: 'google',
    externalId,
    email: normalizeEmail(data?.email),
    emailVerified: data?.email_verified === 'true' || data?.email_verified === true,
    fullName: getString(data?.name),
    givenName: getString(data?.given_name),
    familyName: getString(data?.family_name),
    avatar: getString(data?.picture),
    locale: getString(data?.locale),
    rawProfile: data,
    accessToken: null,
    accessTokenExpiresIn: null,
    refreshToken: null,
    refreshTokenExpiresIn: null,
    grantedScopes: splitScopes(getString(data?.scope) || undefined, []),
  };
};

const getGoogleUserFromAccessToken = async (
  accessToken: string,
  meta: Partial<OAuthIdentity> = {},
): Promise<OAuthIdentity> => {
  const { data } = await fetchJson('https://www.googleapis.com/oauth2/v2/userinfo', {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  const externalId = getString(data?.id);
  if (!externalId) throw new Error('OAUTH_INVALID_TOKEN');

  return {
    service: 'google',
    externalId,
    email: normalizeEmail(data?.email),
    emailVerified: data?.verified_email === true || data?.verified_email === 'true',
    fullName: getString(data?.name),
    givenName: getString(data?.given_name),
    familyName: getString(data?.family_name),
    avatar: getString(data?.picture),
    locale: getString(data?.locale),
    rawProfile: data,
    accessToken,
    accessTokenExpiresIn: meta.accessTokenExpiresIn ?? null,
    refreshToken: meta.refreshToken ?? null,
    refreshTokenExpiresIn: meta.refreshTokenExpiresIn ?? null,
    grantedScopes: meta.grantedScopes || [],
  };
};

const exchangeGoogleCode = async (
  code: string,
  redirectUri: string,
): Promise<OAuthIdentity> => {
  const config = getGoogleConfig();
  const body = new URLSearchParams({
    code,
    client_id: config.clientId,
    client_secret: config.clientSecret,
    redirect_uri: redirectUri,
    grant_type: 'authorization_code',
  });

  const { data } = await fetchJson('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body,
  });

  const accessToken = getString(data?.access_token);
  if (!accessToken) throw new Error('OAUTH_INVALID_TOKEN');

  return getGoogleUserFromAccessToken(accessToken, {
    accessTokenExpiresIn: Number.isFinite(Number(data?.expires_in)) ? Number(data.expires_in) : null,
    refreshToken: getString(data?.refresh_token),
    refreshTokenExpiresIn: Number.isFinite(Number(data?.refresh_token_expires_in))
      ? Number(data.refresh_token_expires_in)
      : null,
    grantedScopes: splitScopes(getString(data?.scope) || undefined, []),
  });
};

const getGithubEmails = async (accessToken: string): Promise<{
  email: string | null;
  verified: boolean;
}> => {
  const { data } = await fetchJson('https://api.github.com/user/emails', {
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${accessToken}`,
      'User-Agent': 'the-api-users',
      'X-GitHub-Api-Version': GITHUB_API_VERSION,
    },
  });

  const emails = Array.isArray(data) ? data : [];
  const primary = emails.find((item) => item?.primary === true)
    || emails.find((item) => item?.verified === true)
    || emails.find((item) => typeof item?.email === 'string');

  return {
    email: normalizeEmail(primary?.email),
    verified: !!primary?.verified,
  };
};

const getGithubUserFromAccessToken = async (
  accessToken: string,
  meta: Partial<OAuthIdentity> = {},
): Promise<OAuthIdentity> => {
  const { data, response } = await fetchJson('https://api.github.com/user', {
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${accessToken}`,
      'User-Agent': 'the-api-users',
      'X-GitHub-Api-Version': GITHUB_API_VERSION,
    },
  });

  const externalId = getString(data?.id);
  if (!externalId) throw new Error('OAUTH_INVALID_TOKEN');

  const emailInfo = await getGithubEmails(accessToken);
  const grantedScopes = meta.grantedScopes
    || splitScopes(response.headers.get('x-oauth-scopes') || undefined, []);

  return {
    service: 'github',
    externalId,
    email: normalizeEmail(data?.email) || emailInfo.email,
    emailVerified: emailInfo.verified,
    fullName: getString(data?.name),
    username: getString(data?.login),
    avatar: getString(data?.avatar_url),
    locale: null,
    rawProfile: {
      ...data,
      emails: emailInfo.email ? [emailInfo.email] : [],
    },
    accessToken,
    accessTokenExpiresIn: meta.accessTokenExpiresIn ?? null,
    refreshToken: meta.refreshToken ?? null,
    refreshTokenExpiresIn: meta.refreshTokenExpiresIn ?? null,
    grantedScopes,
  };
};

const exchangeGithubCode = async (
  code: string,
  redirectUri: string,
): Promise<OAuthIdentity> => {
  const config = getGithubConfig();
  const body = new URLSearchParams({
    client_id: config.clientId,
    client_secret: config.clientSecret,
    code,
    redirect_uri: redirectUri,
  });

  const { data } = await fetchJson('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body,
  });

  const accessToken = getString(data?.access_token);
  if (!accessToken) throw new Error('OAUTH_INVALID_TOKEN');

  return getGithubUserFromAccessToken(accessToken, {
    accessTokenExpiresIn: Number.isFinite(Number(data?.expires_in)) ? Number(data.expires_in) : null,
    refreshToken: getString(data?.refresh_token),
    refreshTokenExpiresIn: Number.isFinite(Number(data?.refresh_token_expires_in))
      ? Number(data.refresh_token_expires_in)
      : null,
    grantedScopes: splitScopes(getString(data?.scope) || undefined, []),
  });
};

const getFacebookUserFromAccessToken = async (
  accessToken: string,
  meta: Partial<OAuthIdentity> = {},
): Promise<OAuthIdentity> => {
  const config = getFacebookConfig();
  const { data } = await fetchJson(`https://graph.facebook.com/${FACEBOOK_API_VERSION}/me?${toQueryString({
    fields: (config.fields || []).join(','),
    access_token: accessToken,
  })}`);

  const externalId = getString(data?.id);
  if (!externalId) throw new Error('OAUTH_INVALID_TOKEN');

  return {
    service: 'facebook',
    externalId,
    email: normalizeEmail(data?.email),
    emailVerified: !!normalizeEmail(data?.email),
    fullName: getString(data?.name),
    givenName: getString(data?.first_name),
    familyName: getString(data?.last_name),
    avatar: getString(data?.picture?.data?.url),
    locale: getString(data?.locale),
    rawProfile: data,
    accessToken,
    accessTokenExpiresIn: meta.accessTokenExpiresIn ?? null,
    refreshToken: meta.refreshToken ?? null,
    refreshTokenExpiresIn: meta.refreshTokenExpiresIn ?? null,
    grantedScopes: meta.grantedScopes || [],
  };
};

const exchangeFacebookCode = async (
  code: string,
  redirectUri: string,
): Promise<OAuthIdentity> => {
  const config = getFacebookConfig();
  const { data } = await fetchJson(`https://graph.facebook.com/${FACEBOOK_API_VERSION}/oauth/access_token?${toQueryString({
    client_id: config.clientId,
    client_secret: config.clientSecret,
    redirect_uri: redirectUri,
    code,
  })}`);

  const accessToken = getString(data?.access_token);
  if (!accessToken) throw new Error('OAUTH_INVALID_TOKEN');

  return getFacebookUserFromAccessToken(accessToken, {
    accessTokenExpiresIn: Number.isFinite(Number(data?.expires_in)) ? Number(data.expires_in) : null,
  });
};

const getLinkedinUserFromAccessToken = async (
  accessToken: string,
  meta: Partial<OAuthIdentity> = {},
): Promise<OAuthIdentity> => {
  const { data } = await fetchJson('https://api.linkedin.com/v2/userinfo', {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  const externalId = getString(data?.sub);
  if (!externalId) throw new Error('OAUTH_INVALID_TOKEN');

  return {
    service: 'linkedin',
    externalId,
    email: normalizeEmail(data?.email),
    emailVerified: data?.email_verified === true || data?.email_verified === 'true',
    fullName: getString(data?.name),
    givenName: getString(data?.given_name),
    familyName: getString(data?.family_name),
    avatar: getString(data?.picture),
    locale: getString(data?.locale),
    rawProfile: data,
    accessToken,
    accessTokenExpiresIn: meta.accessTokenExpiresIn ?? null,
    refreshToken: meta.refreshToken ?? null,
    refreshTokenExpiresIn: meta.refreshTokenExpiresIn ?? null,
    grantedScopes: meta.grantedScopes || [],
  };
};

const exchangeLinkedinCode = async (
  code: string,
  redirectUri: string,
): Promise<OAuthIdentity> => {
  const config = getLinkedinConfig();
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    client_id: config.clientId,
    client_secret: config.clientSecret,
    redirect_uri: redirectUri,
  });

  const { data } = await fetchJson('https://www.linkedin.com/oauth/v2/accessToken', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body,
  });

  const accessToken = getString(data?.access_token);
  if (!accessToken) throw new Error('OAUTH_INVALID_TOKEN');

  return getLinkedinUserFromAccessToken(accessToken, {
    accessTokenExpiresIn: Number.isFinite(Number(data?.expires_in)) ? Number(data.expires_in) : null,
    refreshToken: getString(data?.refresh_token),
    refreshTokenExpiresIn: Number.isFinite(Number(data?.refresh_token_expires_in))
      ? Number(data.refresh_token_expires_in)
      : null,
    grantedScopes: splitScopes(getString(data?.scope) || undefined, []),
  });
};

const getTwitterUserFromAccessToken = async (
  accessToken: string,
  meta: Partial<OAuthIdentity> = {},
): Promise<OAuthIdentity> => {
  const config = getTwitterConfig();
  const { data } = await fetchJson(`https://api.twitter.com/2/users/me?${toQueryString({
    'user.fields': (config.fields || []).join(','),
  })}`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  const userData = data?.data || data;
  const externalId = getString(userData?.id);
  if (!externalId) throw new Error('OAUTH_INVALID_TOKEN');

  return {
    service: 'twitter',
    externalId,
    email: null,
    emailVerified: false,
    fullName: getString(userData?.name),
    username: getString(userData?.username),
    avatar: getString(userData?.profile_image_url),
    locale: null,
    rawProfile: userData,
    accessToken,
    accessTokenExpiresIn: meta.accessTokenExpiresIn ?? null,
    refreshToken: meta.refreshToken ?? null,
    refreshTokenExpiresIn: meta.refreshTokenExpiresIn ?? null,
    grantedScopes: meta.grantedScopes || [],
  };
};

const exchangeTwitterCode = async (
  code: string,
  redirectUri: string,
  codeVerifier: string,
): Promise<OAuthIdentity> => {
  const config = getTwitterConfig();
  const body = new URLSearchParams({
    code,
    grant_type: 'authorization_code',
    client_id: config.clientId,
    redirect_uri: redirectUri,
    code_verifier: codeVerifier,
  });

  const { data } = await fetchJson('https://api.twitter.com/2/oauth2/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: `Basic ${Buffer.from(`${encodeURIComponent(config.clientId)}:${encodeURIComponent(config.clientSecret)}`).toString('base64')}`,
    },
    body,
  });

  const accessToken = getString(data?.access_token);
  if (!accessToken) throw new Error('OAUTH_INVALID_TOKEN');

  return getTwitterUserFromAccessToken(accessToken, {
    accessTokenExpiresIn: Number.isFinite(Number(data?.expires_in)) ? Number(data.expires_in) : null,
    refreshToken: getString(data?.refresh_token),
    refreshTokenExpiresIn: null,
    grantedScopes: splitScopes(getString(data?.scope) || undefined, []),
  });
};

const getMicrosoftUserFromAccessToken = async (
  accessToken: string,
  meta: Partial<OAuthIdentity> = {},
): Promise<OAuthIdentity> => {
  const { data } = await fetchJson('https://graph.microsoft.com/v1.0/me?$select=id,displayName,givenName,surname,mail,userPrincipalName', {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  const externalId = getString(data?.id);
  if (!externalId) throw new Error('OAUTH_INVALID_TOKEN');

  const email = normalizeEmail(data?.mail) || normalizeEmail(data?.userPrincipalName);

  return {
    service: 'microsoft',
    externalId,
    email,
    emailVerified: !!email,
    fullName: getString(data?.displayName),
    givenName: getString(data?.givenName),
    familyName: getString(data?.surname),
    avatar: null,
    locale: null,
    rawProfile: data,
    accessToken,
    accessTokenExpiresIn: meta.accessTokenExpiresIn ?? null,
    refreshToken: meta.refreshToken ?? null,
    refreshTokenExpiresIn: meta.refreshTokenExpiresIn ?? null,
    grantedScopes: meta.grantedScopes || [],
  };
};

const exchangeMicrosoftCode = async (
  code: string,
  redirectUri: string,
): Promise<OAuthIdentity> => {
  const config = getMicrosoftConfig();
  const body = new URLSearchParams({
    client_id: config.clientId,
    client_secret: config.clientSecret,
    redirect_uri: redirectUri,
    code,
    grant_type: 'authorization_code',
  });

  const { data } = await fetchJson(`https://login.microsoftonline.com/${config.tenantId}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body,
  });

  const accessToken = getString(data?.access_token);
  if (!accessToken) throw new Error('OAUTH_INVALID_TOKEN');

  return getMicrosoftUserFromAccessToken(accessToken, {
    accessTokenExpiresIn: Number.isFinite(Number(data?.expires_in)) ? Number(data.expires_in) : null,
    refreshToken: getString(data?.refresh_token),
    refreshTokenExpiresIn: null,
    grantedScopes: splitScopes(getString(data?.scope) || undefined, []),
  });
};

const getAppleJwks = async (): Promise<Array<Record<string, any>>> => {
  const { data } = await fetchJson('https://appleid.apple.com/auth/keys');
  return Array.isArray(data?.keys) ? data.keys : [];
};

const verifyAppleIdToken = async (
  idToken: string,
  extraUser?: unknown,
): Promise<OAuthIdentity> => {
  const decoded = decodeJwt(idToken);
  const config = getAppleConfig();
  const now = Math.floor(Date.now() / 1000);

  if (decoded.header.alg !== 'RS256' || !decoded.header.kid) {
    throw new Error('OAUTH_INVALID_TOKEN');
  }

  const keys = await getAppleJwks();
  const jwk = keys.find((key) => key?.kid === decoded.header.kid && key?.kty === 'RSA');
  if (!jwk) throw new Error('OAUTH_INVALID_TOKEN');

  const isValid = cryptoVerify(
    'RSA-SHA256',
    Buffer.from(decoded.signingInput),
    createPublicKey({ key: jwk, format: 'jwk' }),
    decoded.signature,
  );

  if (!isValid) throw new Error('OAUTH_INVALID_TOKEN');
  if (decoded.payload.iss !== APPLE_AUDIENCE) throw new Error('OAUTH_INVALID_TOKEN');
  if (decoded.payload.aud !== config.clientId) throw new Error('OAUTH_INVALID_TOKEN');
  if (!decoded.payload.exp || Number(decoded.payload.exp) <= now) throw new Error('OAUTH_INVALID_TOKEN');

  const extra = typeof extraUser === 'string'
    ? parseJson<Record<string, any>>(extraUser)
    : (extraUser && typeof extraUser === 'object' ? extraUser as Record<string, any> : null);

  const parsedName = extra?.name || {};
  const email = normalizeEmail(decoded.payload.email);
  const externalId = getString(decoded.payload.sub);
  if (!externalId) throw new Error('OAUTH_INVALID_TOKEN');

  const givenName = getString(parsedName?.firstName);
  const familyName = getString(parsedName?.lastName);
  const fullName = [givenName, familyName].filter(Boolean).join(' ') || getString(extra?.fullName);

  return {
    service: 'apple',
    externalId,
    email,
    emailVerified: decoded.payload.email_verified === true || decoded.payload.email_verified === 'true',
    fullName: fullName || null,
    givenName,
    familyName,
    avatar: null,
    locale: null,
    rawProfile: {
      ...decoded.payload,
      user: extra || undefined,
    },
    accessToken: null,
    accessTokenExpiresIn: null,
    refreshToken: null,
    refreshTokenExpiresIn: null,
    grantedScopes: splitScopes(getString(decoded.payload.scope) || undefined, []),
  };
};

const exchangeAppleCode = async (
  code: string,
  redirectUri: string,
  extraUser?: unknown,
): Promise<OAuthIdentity> => {
  const config = getAppleConfig();
  const body = new URLSearchParams({
    client_id: config.clientId,
    client_secret: config.clientSecret,
    code,
    grant_type: 'authorization_code',
    redirect_uri: redirectUri,
  });

  const { data } = await fetchJson('https://appleid.apple.com/auth/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body,
  });

  const idToken = getString(data?.id_token);
  if (!idToken) throw new Error('OAUTH_INVALID_TOKEN');

  const identity = await verifyAppleIdToken(idToken, extraUser);
  return {
    ...identity,
    accessToken: getString(data?.access_token),
    accessTokenExpiresIn: Number.isFinite(Number(data?.expires_in)) ? Number(data.expires_in) : null,
    refreshToken: getString(data?.refresh_token),
    refreshTokenExpiresIn: null,
  };
};

export const getOAuthAuthorizationUrl = (
  serviceName: string,
  stateOverride?: string,
): { service: OAuthServiceName; state: string; url: string; codeVerifier?: string } => {
  const service = ensureService(serviceName);
  const state = stateOverride || createOAuthState();
  const config = getServiceConfig(service);

  if (service === 'google') {
    const url = `https://accounts.google.com/o/oauth2/v2/auth?${toQueryString({
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      response_type: 'code',
      scope: config.scope.join(' '),
      state,
      include_granted_scopes: 'true',
      access_type: getString(process.env.AUTH_GOOGLE_ACCESS_TYPE) || 'offline',
      prompt: getString(process.env.AUTH_GOOGLE_PROMPT) || undefined,
    })}`;
    return { service, state, url };
  }

  if (service === 'apple') {
    const url = `https://appleid.apple.com/auth/authorize?${toQueryString({
      response_type: 'code',
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      scope: config.scope.join(' '),
      state,
      response_mode: 'form_post',
    })}`;
    return { service, state, url };
  }

  if (service === 'github') {
    const url = `https://github.com/login/oauth/authorize?${toQueryString({
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      scope: config.scope.join(' '),
      state,
    })}`;
    return { service, state, url };
  }

  if (service === 'facebook') {
    const url = `https://www.facebook.com/${FACEBOOK_API_VERSION}/dialog/oauth?${toQueryString({
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      response_type: 'code',
      scope: config.scope.join(','),
      state,
    })}`;
    return { service, state, url };
  }

  if (service === 'linkedin') {
    const url = `https://www.linkedin.com/oauth/v2/authorization?${toQueryString({
      response_type: 'code',
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      scope: config.scope.join(' '),
      state,
    })}`;
    return { service, state, url };
  }

  if (service === 'microsoft') {
    const url = `https://login.microsoftonline.com/${config.tenantId}/oauth2/v2.0/authorize?${toQueryString({
      response_type: 'code',
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      scope: config.scope.join(' '),
      include_granted_scopes: 'true',
      state,
    })}`;
    return { service, state, url };
  }

  const codeVerifier = createCodeVerifier();
  const codeChallenge = createCodeChallenge(codeVerifier);
  const url = `https://x.com/i/oauth2/authorize?${toQueryString({
    response_type: 'code',
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    scope: config.scope.join(' '),
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  })}`;

  return { service, state, url, codeVerifier };
};

export const assertOAuthServiceName = (serviceName: string): OAuthServiceName => ensureService(serviceName);

export const isOAuthServiceConfigured = (serviceName: string): boolean => {
  const service = ensureService(serviceName);

  try {
    getServiceConfig(service);
    return true;
  } catch (error) {
    if (error instanceof Error && error.message === 'OAUTH_CONFIG_NOT_FOUND') {
      return false;
    }

    throw error;
  }
};

export const rememberOAuthState = (c: AppContext, service: OAuthServiceName, state: string): void => {
  setOAuthStateCookie(c, service, state);
};

export const rememberOAuthCodeVerifier = (
  c: AppContext,
  service: OAuthServiceName,
  codeVerifier: string,
): void => {
  setOAuthTempCookie(c, service, 'code_verifier', codeVerifier);
};

export const getOAuthCodeVerifier = (
  c: AppContext,
  service: OAuthServiceName,
): string | null => getCookie(c, getOAuthTempCookieName(service, 'code_verifier')) || null;

export const clearOAuthCodeVerifier = (
  c: AppContext,
  service: OAuthServiceName,
): void => {
  setCookie(c, getOAuthTempCookieName(service, 'code_verifier'), '', {
    httpOnly: true,
    path: '/',
    sameSite: 'Lax',
    secure: c.req.url.startsWith('https://'),
    maxAge: 0,
  });
};

export const resolveOAuthIdentity = async (
  serviceName: string,
  payload: OAuthExchangePayload,
): Promise<OAuthIdentity> => {
  const service = ensureService(serviceName);
  const config = getServiceConfig(service);
  const redirectUri = getString(payload.redirectUri) || config.redirectUri;

  if (config.redirectUri && redirectUri !== config.redirectUri) {
    throw new Error('OAUTH_INVALID_REDIRECT_URI');
  }

  const code = getString(payload.code);
  const accessToken = getString(payload.accessToken);
  const idToken = getString(payload.idToken);
  const codeVerifier = getString(payload.codeVerifier);
  const user = payload.user;

  if (service === 'apple') {
    if (code) return exchangeAppleCode(code, redirectUri, user);
    if (idToken) return verifyAppleIdToken(idToken, user);
    throw new Error('OAUTH_TOKEN_REQUIRED');
  }

  if (service === 'google') {
    if (code) return exchangeGoogleCode(code, redirectUri);
    if (accessToken) return getGoogleUserFromAccessToken(accessToken);
    if (idToken) return verifyGoogleIdToken(idToken);
    throw new Error('OAUTH_TOKEN_REQUIRED');
  }

  if (service === 'github') {
    if (code) return exchangeGithubCode(code, redirectUri);
    if (accessToken) return getGithubUserFromAccessToken(accessToken);
    throw new Error('OAUTH_TOKEN_REQUIRED');
  }

  if (service === 'facebook') {
    if (code) return exchangeFacebookCode(code, redirectUri);
    if (accessToken) return getFacebookUserFromAccessToken(accessToken);
    throw new Error('OAUTH_TOKEN_REQUIRED');
  }

  if (service === 'linkedin') {
    if (code) return exchangeLinkedinCode(code, redirectUri);
    if (accessToken) return getLinkedinUserFromAccessToken(accessToken);
    throw new Error('OAUTH_TOKEN_REQUIRED');
  }

  if (service === 'microsoft') {
    if (code) return exchangeMicrosoftCode(code, redirectUri);
    if (accessToken) return getMicrosoftUserFromAccessToken(accessToken);
    throw new Error('OAUTH_TOKEN_REQUIRED');
  }

  if (code) {
    if (!codeVerifier) throw new Error('OAUTH_INVALID_TOKEN');
    return exchangeTwitterCode(code, redirectUri, codeVerifier);
  }
  if (accessToken) return getTwitterUserFromAccessToken(accessToken);
  throw new Error('OAUTH_TOKEN_REQUIRED');
};

const parseProviders = (value: unknown): OAuthProvidersMap => {
  if (!value) return {};

  if (typeof value === 'string') {
    try {
      return parseProviders(JSON.parse(value));
    } catch {
      return {};
    }
  }

  if (typeof value !== 'object' || Array.isArray(value)) return {};

  const result: OAuthProvidersMap = {};
  for (const service of OAUTH_SERVICES) {
    const record = (value as Record<string, unknown>)[service];
    if (record && typeof record === 'object' && !Array.isArray(record)) {
      result[service] = record as OAuthProviderRecord;
    }
  }

  return result;
};

export const normalizeOAuthProviders = (value: unknown): OAuthProvidersMap => parseProviders(value);

export const getOAuthServices = (value: unknown): OAuthServiceName[] =>
  OAUTH_SERVICES.filter((service) => !!normalizeOAuthProviders(value)[service]);

export const getOAuthServiceSummaries = (
  value: unknown,
): Array<Pick<OAuthProviderRecord, 'service' | 'email' | 'phone' | 'fullName' | 'avatar' | 'linkedAt' | 'updatedAt'>> => {
  const providers = normalizeOAuthProviders(value);

  return OAUTH_SERVICES
    .map((service) => providers[service])
    .filter(Boolean)
    .map((provider) => ({
      service: provider!.service,
      email: provider!.email,
      phone: provider!.phone,
      fullName: provider!.fullName,
      avatar: provider!.avatar,
      linkedAt: provider!.linkedAt,
      updatedAt: provider!.updatedAt,
    }));
};

export const buildOAuthProviderRecord = (
  identity: OAuthIdentity,
  linkedAt?: string,
): OAuthProviderRecord => ({
  service: identity.service,
  externalId: identity.externalId,
  email: identity.email || null,
  emailVerified: !!identity.email,
  phone: normalizePhone(identity.phone) || null,
  phoneVerified: !!normalizePhone(identity.phone),
  fullName: identity.fullName || null,
  givenName: identity.givenName || null,
  familyName: identity.familyName || null,
  username: identity.username || null,
  avatar: identity.avatar || null,
  locale: identity.locale || null,
  grantedScopes: identity.grantedScopes || [],
  linkedAt: linkedAt || new Date().toISOString(),
  updatedAt: new Date().toISOString(),
  profile: identity.rawProfile,
});

export const withOAuthProvider = (
  value: unknown,
  identity: OAuthIdentity,
): OAuthProvidersMap => {
  const providers = normalizeOAuthProviders(value);
  const existing = providers[identity.service];

  return {
    ...providers,
    [identity.service]: buildOAuthProviderRecord(identity, existing?.linkedAt),
  };
};

export const withoutOAuthProvider = (
  value: unknown,
  serviceName: string,
): OAuthProvidersMap => {
  const service = ensureService(serviceName);
  const providers = normalizeOAuthProviders(value);
  const nextProviders = { ...providers };
  delete nextProviders[service];
  return nextProviders;
};

export const findUserByOAuthService = async (
  c: AppContext,
  serviceName: string,
  externalId: string,
): Promise<UserRecord | undefined> => {
  const service = ensureService(serviceName);
  const db = getDb(c);
  const clientName = String(db.client.config.client || '');

  if (clientName.includes('pg')) {
    return db('users')
      .whereRaw('("oauthProviders" -> ?) ->> \'externalId\' = ?', [service, externalId])
      .first() as Promise<UserRecord | undefined>;
  }

  const users = await db('users')
    .whereNotNull('oauthProviders')
    .select('*') as UserRecord[];

  return users.find((user) => normalizeOAuthProviders(user.oauthProviders)[service]?.externalId === externalId);
};
