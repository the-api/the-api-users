// src/index.ts
import { dirname as dirname2, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// src/modules/login.ts
import { Routings } from "the-api-routings";

// src/lib/oauth.ts
import {
  createHash as createHash2,
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify
} from "node:crypto";

// node_modules/hono/dist/utils/url.js
var tryDecode = (str, decoder) => {
  try {
    return decoder(str);
  } catch {
    return str.replace(/(?:%[0-9A-Fa-f]{2})+/g, (match) => {
      try {
        return decoder(match);
      } catch {
        return match;
      }
    });
  }
};
var decodeURIComponent_ = decodeURIComponent;

// node_modules/hono/dist/utils/cookie.js
var validCookieNameRegEx = /^[\w!#$%&'*.^`|~+-]+$/;
var validCookieValueRegEx = /^[ !#-:<-[\]-~]*$/;
var parse = (cookie, name) => {
  if (name && cookie.indexOf(name) === -1) {
    return {};
  }
  const pairs = cookie.trim().split(";");
  const parsedCookie = {};
  for (let pairStr of pairs) {
    pairStr = pairStr.trim();
    const valueStartPos = pairStr.indexOf("=");
    if (valueStartPos === -1) {
      continue;
    }
    const cookieName = pairStr.substring(0, valueStartPos).trim();
    if (name && name !== cookieName || !validCookieNameRegEx.test(cookieName)) {
      continue;
    }
    let cookieValue = pairStr.substring(valueStartPos + 1).trim();
    if (cookieValue.startsWith('"') && cookieValue.endsWith('"')) {
      cookieValue = cookieValue.slice(1, -1);
    }
    if (validCookieValueRegEx.test(cookieValue)) {
      parsedCookie[cookieName] = cookieValue.indexOf("%") !== -1 ? tryDecode(cookieValue, decodeURIComponent_) : cookieValue;
      if (name) {
        break;
      }
    }
  }
  return parsedCookie;
};
var _serialize = (name, value, opt = {}) => {
  let cookie = `${name}=${value}`;
  if (name.startsWith("__Secure-") && !opt.secure) {
    throw new Error("__Secure- Cookie must have Secure attributes");
  }
  if (name.startsWith("__Host-")) {
    if (!opt.secure) {
      throw new Error("__Host- Cookie must have Secure attributes");
    }
    if (opt.path !== "/") {
      throw new Error('__Host- Cookie must have Path attributes with "/"');
    }
    if (opt.domain) {
      throw new Error("__Host- Cookie must not have Domain attributes");
    }
  }
  for (const key of ["domain", "path"]) {
    if (opt[key] && /[;\r\n]/.test(opt[key])) {
      throw new Error(`${key} must not contain ";", "\\r", or "\\n"`);
    }
  }
  if (opt && typeof opt.maxAge === "number" && opt.maxAge >= 0) {
    if (opt.maxAge > 34560000) {
      throw new Error("Cookies Max-Age SHOULD NOT be greater than 400 days (34560000 seconds) in duration.");
    }
    cookie += `; Max-Age=${opt.maxAge | 0}`;
  }
  if (opt.domain && opt.prefix !== "host") {
    cookie += `; Domain=${opt.domain}`;
  }
  if (opt.path) {
    cookie += `; Path=${opt.path}`;
  }
  if (opt.expires) {
    if (opt.expires.getTime() - Date.now() > 34560000000) {
      throw new Error("Cookies Expires SHOULD NOT be greater than 400 days (34560000 seconds) in the future.");
    }
    cookie += `; Expires=${opt.expires.toUTCString()}`;
  }
  if (opt.httpOnly) {
    cookie += "; HttpOnly";
  }
  if (opt.secure) {
    cookie += "; Secure";
  }
  if (opt.sameSite) {
    cookie += `; SameSite=${opt.sameSite.charAt(0).toUpperCase() + opt.sameSite.slice(1)}`;
  }
  if (opt.priority) {
    cookie += `; Priority=${opt.priority.charAt(0).toUpperCase() + opt.priority.slice(1)}`;
  }
  if (opt.partitioned) {
    if (!opt.secure) {
      throw new Error("Partitioned Cookie must have Secure attributes");
    }
    cookie += "; Partitioned";
  }
  return cookie;
};
var serialize = (name, value, opt) => {
  value = encodeURIComponent(value);
  return _serialize(name, value, opt);
};

// node_modules/hono/dist/helper/cookie/index.js
var getCookie = (c, key, prefix) => {
  const cookie = c.req.raw.headers.get("Cookie");
  if (typeof key === "string") {
    if (!cookie) {
      return;
    }
    let finalKey = key;
    if (prefix === "secure") {
      finalKey = "__Secure-" + key;
    } else if (prefix === "host") {
      finalKey = "__Host-" + key;
    }
    const obj2 = parse(cookie, finalKey);
    return obj2[finalKey];
  }
  if (!cookie) {
    return {};
  }
  const obj = parse(cookie);
  return obj;
};
var generateCookie = (name, value, opt) => {
  let cookie;
  if (opt?.prefix === "secure") {
    cookie = serialize("__Secure-" + name, value, { path: "/", ...opt, secure: true });
  } else if (opt?.prefix === "host") {
    cookie = serialize("__Host-" + name, value, {
      ...opt,
      path: "/",
      secure: true,
      domain: undefined
    });
  } else {
    cookie = serialize(name, value, { path: "/", ...opt });
  }
  return cookie;
};
var setCookie = (c, name, value, opt) => {
  const cookie = generateCookie(name, value, opt);
  c.header("Set-Cookie", cookie, { append: true });
};

// src/lib/auth.ts
import {
  createHash,
  createHmac,
  randomBytes,
  scryptSync,
  timingSafeEqual
} from "node:crypto";
var ONE_SECOND = 1000;
var DEFAULT_PASSWORD_HASH_ALGORITHM = "scrypt";
var DEFAULT_SCRYPT_OPTIONS = {
  N: 16384,
  r: 8,
  p: 1,
  maxmem: 32 * 1024 * 1024
};
var DURATION_UNITS = {
  s: 1,
  m: 60,
  h: 60 * 60,
  d: 24 * 60 * 60
};
var base64UrlEncode = (value) => Buffer.from(value).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
var getDurationSeconds = (value, fallback) => {
  if (typeof value === "number" && Number.isFinite(value)) {
    return Math.max(1, Math.floor(value));
  }
  if (typeof value !== "string" || !value.trim())
    return fallback;
  const trimmed = value.trim();
  const plain = Number(trimmed);
  if (Number.isFinite(plain))
    return Math.max(1, Math.floor(plain));
  const match = trimmed.match(/^(\d+)([smhd])$/i);
  if (!match)
    return fallback;
  const amount = Number(match[1]);
  const unit = DURATION_UNITS[match[2].toLowerCase()];
  if (!Number.isFinite(amount) || !unit)
    return fallback;
  return amount * unit;
};
var getExpiresAt = (value, fallback) => new Date(Date.now() + getDurationSeconds(value, fallback) * ONE_SECOND);
var isExpired = (value) => {
  if (!value)
    return true;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) || date.getTime() <= Date.now();
};
var randomToken = (bytes = 32) => base64UrlEncode(randomBytes(bytes));
var randomCode = (length = 6) => {
  const numbers = Array.from({ length }, () => Math.floor(Math.random() * 10));
  return numbers.join("");
};
var randomSalt = () => randomToken(16);
var getPasswordHashAlgorithm = () => {
  const value = process.env.AUTH_PASSWORD_HASH_ALGORITHM?.trim().toLowerCase();
  if (value === "sha256")
    return "sha256";
  return DEFAULT_PASSWORD_HASH_ALGORITHM;
};
var isPowerOfTwo = (value) => value > 1 && Number.isInteger(Math.log2(value));
var getIntegerEnv = (key, fallback, isValid = (value) => value > 0) => {
  const raw = process.env[key]?.trim();
  if (!raw)
    return fallback;
  const value = Number(raw);
  return Number.isSafeInteger(value) && isValid(value) ? value : fallback;
};
var getScryptOptions = () => ({
  N: getIntegerEnv("AUTH_SCRYPT_N", DEFAULT_SCRYPT_OPTIONS.N, isPowerOfTwo),
  r: getIntegerEnv("AUTH_SCRYPT_R", DEFAULT_SCRYPT_OPTIONS.r),
  p: getIntegerEnv("AUTH_SCRYPT_P", DEFAULT_SCRYPT_OPTIONS.p),
  maxmem: getIntegerEnv("AUTH_SCRYPT_MAXMEM", DEFAULT_SCRYPT_OPTIONS.maxmem)
});
var hashPassword = (password, salt, algorithm = getPasswordHashAlgorithm()) => {
  if (algorithm === "sha256") {
    return createHash("sha256").update(`${password}${salt}`, "utf8").digest("hex");
  }
  return scryptSync(password, salt, 64, getScryptOptions()).toString("hex");
};
var verifyPassword = (password, salt, hash, algorithm = getPasswordHashAlgorithm()) => {
  const expected = Buffer.from(hash, "hex");
  const actual = Buffer.from(hashPassword(password, salt, algorithm), "hex");
  if (expected.length !== actual.length)
    return false;
  return timingSafeEqual(expected, actual);
};
var normalizeEmail = (value) => {
  if (typeof value !== "string")
    return null;
  const email = value.trim().toLowerCase();
  return email || null;
};
var normalizePhone = (value) => {
  if (typeof value !== "string")
    return null;
  const trimmed = value.trim();
  if (!trimmed)
    return null;
  const normalized = trimmed.replace(/[^\d+]/g, "");
  if (!normalized)
    return null;
  if (normalized.startsWith("+")) {
    return `+${normalized.slice(1).replace(/\D/g, "")}` || null;
  }
  return normalized.replace(/\D/g, "") || null;
};
var signJwt = (payload, {
  secret = process.env.JWT_SECRET || "",
  expiresIn = process.env.JWT_EXPIRES_IN || "1h"
} = {}) => {
  const now = Math.floor(Date.now() / ONE_SECOND);
  const exp = now + getDurationSeconds(expiresIn, 60 * 60);
  const header = { alg: "HS256", typ: "JWT" };
  const body = { ...payload, iat: now, exp };
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(body));
  const signature = createHmac("sha256", secret).update(`${encodedHeader}.${encodedPayload}`).digest();
  return `${encodedHeader}.${encodedPayload}.${base64UrlEncode(signature)}`;
};

// src/lib/runtime.ts
import { mkdir, unlink, writeFile } from "node:fs/promises";
import { basename, dirname, extname, join, posix } from "node:path";
var FILES_FOLDER = process.env.FILES_FOLDER || "";
var VERIFIED_ROLE = process.env.AUTH_VERIFIED_ROLE || process.env.AUTH_DEFAULT_ROLE || "registered";
var UNVERIFIED_ROLE = process.env.AUTH_UNVERIFIED_ROLE || "unverified";
var getRolesService = (c) => c.var.roles || c.env.roles;
var getDb = (c) => {
  const db = c.var.db || c.env.db;
  if (!db)
    throw new Error("DB_CONNECTION_REQUIRED");
  return db;
};
var getDbWrite = (c) => {
  const db = c.var.dbWrite || c.env.dbWrite || c.var.db || c.env.db;
  if (!db)
    throw new Error("DB_WRITE_CONNECTION_REQUIRED");
  return db;
};
var getRequestUser = (c) => c.var.user || {};
var requireAuth = (c) => {
  const user = getRequestUser(c);
  if (!user.id || !Array.isArray(user.roles) || user.roles.includes("guest")) {
    throw new Error("NO_TOKEN");
  }
  return user;
};
var isUserIdentityVerified = (user) => {
  if (!user)
    return false;
  if (user.isEmailVerified && !!user.email)
    return true;
  if (user.isPhoneVerified && !!user.phone)
    return true;
  return !!user.role && String(user.role) !== UNVERIFIED_ROLE;
};
var getUserRoles = (user) => {
  const roles = Array.isArray(user?.roles) ? user?.roles : user?.role ? [String(user.role)] : [isUserIdentityVerified(user) ? VERIFIED_ROLE : UNVERIFIED_ROLE];
  return Array.from(new Set(roles.filter(Boolean).map(String)));
};
var hasPermission = (c, permission, roles = getUserRoles(getRequestUser(c))) => {
  const service = getRolesService(c);
  if (!service)
    return true;
  const permissions = service.getPermissions(roles);
  return service.checkWildcardPermissions({ key: permission, permissions });
};
var sanitizeUser = ({
  c,
  user,
  hiddenFields,
  visibleFor = {},
  ownerPermissions = []
}) => {
  const requestUser = getRequestUser(c);
  const service = getRolesService(c);
  const result = { ...user };
  const hidden = new Set(hiddenFields);
  if (!service) {
    for (const field of hidden)
      delete result[field];
    return result;
  }
  const permissions = service.getPermissions(getUserRoles(requestUser));
  const ownerPermissionMap = service.getPermissions(ownerPermissions);
  const isOwner = !!requestUser.id && `${requestUser.id}` === `${user.id}`;
  for (const [permission, fields] of Object.entries(visibleFor)) {
    const canSee = service.checkWildcardPermissions({
      key: permission,
      permissions: isOwner ? { ...permissions, ...ownerPermissionMap } : permissions
    });
    if (canSee) {
      for (const field of fields)
        hidden.delete(field);
    }
  }
  for (const field of hidden)
    delete result[field];
  return result;
};
var sendEmail = async (c, params) => {
  const email = c.var.email;
  if (email) {
    await email(params);
    return;
  }
  c.var.log?.("Email delivery skipped, no email middleware configured", params);
};
var sendSms = async (c, {
  to,
  body
}) => {
  const {
    SMS_PROVIDER,
    TWILIO_ACCOUNT_SID,
    TWILIO_AUTH_TOKEN,
    TWILIO_FROM
  } = process.env;
  if ((SMS_PROVIDER === "twilio" || !SMS_PROVIDER && TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN && TWILIO_FROM) && TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN && TWILIO_FROM) {
    const endpoint = `https://api.twilio.com/2010-04-01/Accounts/${TWILIO_ACCOUNT_SID}/Messages.json`;
    const form = new URLSearchParams({ To: to, From: TWILIO_FROM, Body: body });
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        Authorization: `Basic ${Buffer.from(`${TWILIO_ACCOUNT_SID}:${TWILIO_AUTH_TOKEN}`).toString("base64")}`,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: form
    });
    if (!response.ok) {
      const errorText = await response.text();
      c.var.log?.("SMS delivery failed", errorText);
      throw new Error("SMS_SEND_FAILED");
    }
    return;
  }
  c.var.log?.("SMS delivery skipped, no SMS provider configured", { to, body });
};
var createStoredFile = async (file, destDir) => {
  if (!FILES_FOLDER)
    throw new Error("FILES_NO_STORAGE_CONFIGURED");
  const extension = extname(file.name) || "";
  const fileName = `${randomToken(12)}${extension}`;
  const relativePath = posix.join(destDir.replace(/\\/g, "/"), fileName);
  const fullPath = join(FILES_FOLDER, relativePath);
  await mkdir(dirname(fullPath), { recursive: true });
  await writeFile(fullPath, Buffer.from(await file.arrayBuffer()));
  return { path: relativePath, name: fileName, size: file.size };
};
var uploadFile = async (c, file, destDir) => {
  const files = c.var.files;
  if (files?.upload)
    return files.upload(file, destDir);
  return createStoredFile(file, destDir);
};
var deleteStoredFile = async (c, filePath) => {
  if (!filePath)
    return;
  const files = c.var.files;
  if (files?.delete) {
    await files.delete(filePath);
    return;
  }
  if (!FILES_FOLDER)
    return;
  const fullPath = join(FILES_FOLDER, filePath);
  try {
    await unlink(fullPath);
  } catch {
    c.var.log?.("Avatar cleanup skipped", basename(filePath));
  }
};

// src/lib/oauth.ts
var OAUTH_SERVICES = ["apple", "facebook", "github", "google", "linkedin", "microsoft", "twitter"];
var APPLE_AUDIENCE = "https://appleid.apple.com";
var FACEBOOK_API_VERSION = "v18.0";
var GITHUB_API_VERSION = "2022-11-28";
var MICROSOFT_TENANT = "common";
var getString = (value) => {
  if (typeof value === "number" || typeof value === "bigint")
    return String(value);
  if (typeof value !== "string")
    return null;
  const result = value.trim();
  return result || null;
};
var splitScopes = (value, fallback) => {
  const input = getString(value);
  if (!input)
    return fallback;
  return Array.from(new Set(input.split(/[,\s]+/).map((item) => item.trim()).filter(Boolean)));
};
var getEnv = (...keys) => {
  for (const key of keys) {
    const value = getString(process.env[key]);
    if (value)
      return value;
  }
  return null;
};
var getOAuthStateCookieName = (service) => `oauth_state_${service}`;
var getOAuthTempCookieName = (service, key) => `oauth_${key}_${service}`;
var setOAuthStateCookie = (c, service, state) => {
  setCookie(c, getOAuthStateCookieName(service), state, {
    httpOnly: true,
    path: "/",
    sameSite: "Lax",
    secure: c.req.url.startsWith("https://"),
    maxAge: 10 * 60
  });
};
var setOAuthTempCookie = (c, service, key, value) => {
  setCookie(c, getOAuthTempCookieName(service, key), value, {
    httpOnly: true,
    path: "/",
    sameSite: "Lax",
    secure: c.req.url.startsWith("https://"),
    maxAge: 10 * 60
  });
};
var createOAuthState = () => randomToken(18);
var toBase64Url = (value) => value.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
var createCodeVerifier = () => randomToken(48);
var createCodeChallenge = (codeVerifier) => toBase64Url(createHash2("sha256").update(codeVerifier).digest());
var fromBase64Url = (value) => {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Buffer.from(normalized, "base64");
};
var parseJson = (value) => {
  const input = getString(value);
  if (!input)
    return null;
  try {
    return JSON.parse(input);
  } catch {
    return null;
  }
};
var decodeJwt = (token) => {
  const parts = token.split(".");
  if (parts.length !== 3)
    throw new Error("OAUTH_INVALID_TOKEN");
  const [headerPart, payloadPart, signaturePart] = parts;
  const header = parseJson(fromBase64Url(headerPart).toString("utf8"));
  const payload = parseJson(fromBase64Url(payloadPart).toString("utf8"));
  if (!header || !payload)
    throw new Error("OAUTH_INVALID_TOKEN");
  return {
    header,
    payload,
    signingInput: `${headerPart}.${payloadPart}`,
    signature: fromBase64Url(signaturePart)
  };
};
var validateOAuthState = (c, service, state) => {
  const cookieName = getOAuthStateCookieName(service);
  const expected = getCookie(c, cookieName);
  if (!expected)
    return true;
  if (!state)
    return false;
  const isValid = expected === state;
  if (isValid) {
    setCookie(c, cookieName, "", {
      httpOnly: true,
      path: "/",
      sameSite: "Lax",
      secure: c.req.url.startsWith("https://"),
      maxAge: 0
    });
  }
  return isValid;
};
var getGoogleConfig = () => {
  const clientId = getEnv("AUTH_GOOGLE_CLIENT_ID", "GOOGLE_ID");
  const clientSecret = getEnv("AUTH_GOOGLE_CLIENT_SECRET", "GOOGLE_SECRET");
  const redirectUri = getEnv("AUTH_GOOGLE_REDIRECT_URI", "AUTH_GOOGLE_CALLBACK_URL");
  if (!clientId || !clientSecret || !redirectUri)
    throw new Error("OAUTH_CONFIG_NOT_FOUND");
  return {
    clientId,
    clientSecret,
    redirectUri,
    scope: splitScopes(process.env.AUTH_GOOGLE_SCOPE, ["openid", "email", "profile"])
  };
};
var getGithubConfig = () => {
  const clientId = getEnv("AUTH_GITHUB_CLIENT_ID", "GITHUB_ID");
  const clientSecret = getEnv("AUTH_GITHUB_CLIENT_SECRET", "GITHUB_SECRET");
  const redirectUri = getEnv("AUTH_GITHUB_REDIRECT_URI", "AUTH_GITHUB_CALLBACK_URL");
  if (!clientId || !clientSecret || !redirectUri)
    throw new Error("OAUTH_CONFIG_NOT_FOUND");
  return {
    clientId,
    clientSecret,
    redirectUri,
    scope: splitScopes(process.env.AUTH_GITHUB_SCOPE, ["read:user", "user:email"])
  };
};
var getFacebookConfig = () => {
  const clientId = getEnv("AUTH_FACEBOOK_CLIENT_ID", "FACEBOOK_ID");
  const clientSecret = getEnv("AUTH_FACEBOOK_CLIENT_SECRET", "FACEBOOK_SECRET");
  const redirectUri = getEnv("AUTH_FACEBOOK_REDIRECT_URI", "AUTH_FACEBOOK_CALLBACK_URL");
  if (!clientId || !clientSecret || !redirectUri)
    throw new Error("OAUTH_CONFIG_NOT_FOUND");
  return {
    clientId,
    clientSecret,
    redirectUri,
    scope: splitScopes(process.env.AUTH_FACEBOOK_SCOPE, ["email", "public_profile"]),
    fields: splitScopes(process.env.AUTH_FACEBOOK_FIELDS, ["id", "email", "first_name", "last_name", "name", "picture"])
  };
};
var getLinkedinConfig = () => {
  const clientId = getEnv("AUTH_LINKEDIN_CLIENT_ID", "LINKEDIN_ID");
  const clientSecret = getEnv("AUTH_LINKEDIN_CLIENT_SECRET", "LINKEDIN_SECRET");
  const redirectUri = getEnv("AUTH_LINKEDIN_REDIRECT_URI", "AUTH_LINKEDIN_CALLBACK_URL");
  if (!clientId || !clientSecret || !redirectUri)
    throw new Error("OAUTH_CONFIG_NOT_FOUND");
  return {
    clientId,
    clientSecret,
    redirectUri,
    scope: splitScopes(process.env.AUTH_LINKEDIN_SCOPE, ["openid", "profile", "email"])
  };
};
var getTwitterConfig = () => {
  const clientId = getEnv("AUTH_TWITTER_CLIENT_ID", "AUTH_X_CLIENT_ID", "X_ID");
  const clientSecret = getEnv("AUTH_TWITTER_CLIENT_SECRET", "AUTH_X_CLIENT_SECRET", "X_SECRET");
  const redirectUri = getEnv("AUTH_TWITTER_REDIRECT_URI", "AUTH_TWITTER_CALLBACK_URL", "AUTH_X_REDIRECT_URI", "AUTH_X_CALLBACK_URL");
  if (!clientId || !clientSecret || !redirectUri)
    throw new Error("OAUTH_CONFIG_NOT_FOUND");
  return {
    clientId,
    clientSecret,
    redirectUri,
    scope: splitScopes(process.env.AUTH_TWITTER_SCOPE || process.env.AUTH_X_SCOPE, ["tweet.read", "users.read", "offline.access"]),
    fields: splitScopes(process.env.AUTH_TWITTER_FIELDS || process.env.AUTH_X_FIELDS, ["id", "name", "username", "profile_image_url"])
  };
};
var getMicrosoftConfig = () => {
  const clientId = getEnv("AUTH_MICROSOFT_CLIENT_ID", "AUTH_MSENTRA_CLIENT_ID", "MSENTRA_ID");
  const clientSecret = getEnv("AUTH_MICROSOFT_CLIENT_SECRET", "AUTH_MSENTRA_CLIENT_SECRET", "MSENTRA_SECRET");
  const redirectUri = getEnv("AUTH_MICROSOFT_REDIRECT_URI", "AUTH_MICROSOFT_CALLBACK_URL", "AUTH_MSENTRA_REDIRECT_URI", "AUTH_MSENTRA_CALLBACK_URL");
  const tenantId = getEnv("AUTH_MICROSOFT_TENANT_ID", "AUTH_MSENTRA_TENANT_ID") || MICROSOFT_TENANT;
  if (!clientId || !clientSecret || !redirectUri)
    throw new Error("OAUTH_CONFIG_NOT_FOUND");
  return {
    clientId,
    clientSecret,
    redirectUri,
    tenantId,
    scope: splitScopes(process.env.AUTH_MICROSOFT_SCOPE || process.env.AUTH_MSENTRA_SCOPE, ["openid", "profile", "email", "offline_access", "User.Read"])
  };
};
var getApplePrivateKey = () => {
  const privateKey = getString(process.env.AUTH_APPLE_PRIVATE_KEY);
  if (!privateKey)
    return null;
  return privateKey.replace(/\\n/g, `
`);
};
var createAppleClientSecret = () => {
  const clientId = getEnv("AUTH_APPLE_CLIENT_ID");
  const teamId = getEnv("AUTH_APPLE_TEAM_ID");
  const keyId = getEnv("AUTH_APPLE_KEY_ID");
  const privateKey = getApplePrivateKey();
  if (!clientId || !teamId || !keyId || !privateKey) {
    throw new Error("OAUTH_CONFIG_NOT_FOUND");
  }
  const now = Math.floor(Date.now() / 1000);
  const header = {
    alg: "ES256",
    kid: keyId,
    typ: "JWT"
  };
  const payload = {
    iss: teamId,
    iat: now,
    exp: now + 60 * 60 * 24 * 180,
    aud: APPLE_AUDIENCE,
    sub: clientId
  };
  const encodedHeader = toBase64Url(Buffer.from(JSON.stringify(header)));
  const encodedPayload = toBase64Url(Buffer.from(JSON.stringify(payload)));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = cryptoSign("sha256", Buffer.from(signingInput), {
    key: createPrivateKey(privateKey),
    dsaEncoding: "ieee-p1363"
  });
  return `${signingInput}.${toBase64Url(signature)}`;
};
var getAppleConfig = () => {
  const clientId = getEnv("AUTH_APPLE_CLIENT_ID");
  const redirectUri = getEnv("AUTH_APPLE_REDIRECT_URI", "AUTH_APPLE_CALLBACK_URL");
  const clientSecret = getEnv("AUTH_APPLE_CLIENT_SECRET") || createAppleClientSecret();
  if (!clientId || !clientSecret || !redirectUri)
    throw new Error("OAUTH_CONFIG_NOT_FOUND");
  return {
    clientId,
    clientSecret,
    redirectUri,
    scope: splitScopes(process.env.AUTH_APPLE_SCOPE, ["name", "email"])
  };
};
var getServiceConfig = (service) => {
  if (service === "apple")
    return getAppleConfig();
  if (service === "google")
    return getGoogleConfig();
  if (service === "github")
    return getGithubConfig();
  if (service === "facebook")
    return getFacebookConfig();
  if (service === "linkedin")
    return getLinkedinConfig();
  if (service === "microsoft")
    return getMicrosoftConfig();
  return getTwitterConfig();
};
var ensureService = (service) => {
  if (OAUTH_SERVICES.includes(service)) {
    return service;
  }
  throw new Error("OAUTH_SERVICE_NOT_SUPPORTED");
};
var toQueryString = (params) => {
  const search = new URLSearchParams;
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") {
      search.set(key, value);
    }
  }
  return search.toString();
};
var fetchJson = async (url, init) => {
  const response = await fetch(url, init);
  const text = await response.text();
  let data = {};
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      throw new Error("OAUTH_INVALID_TOKEN");
    }
  }
  if (!response.ok) {
    throw new Error("OAUTH_INVALID_TOKEN");
  }
  return { data, response };
};
var verifyGoogleIdToken = async (idToken) => {
  const { data } = await fetchJson(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(idToken)}`);
  const config = getGoogleConfig();
  if (data?.aud && data.aud !== config.clientId) {
    throw new Error("OAUTH_INVALID_TOKEN");
  }
  const externalId = getString(data?.sub);
  if (!externalId)
    throw new Error("OAUTH_INVALID_TOKEN");
  return {
    service: "google",
    externalId,
    email: normalizeEmail(data?.email),
    emailVerified: data?.email_verified === "true" || data?.email_verified === true,
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
    grantedScopes: splitScopes(getString(data?.scope) || undefined, [])
  };
};
var getGoogleUserFromAccessToken = async (accessToken, meta = {}) => {
  const { data } = await fetchJson("https://www.googleapis.com/oauth2/v2/userinfo", {
    headers: {
      Authorization: `Bearer ${accessToken}`
    }
  });
  const externalId = getString(data?.id);
  if (!externalId)
    throw new Error("OAUTH_INVALID_TOKEN");
  return {
    service: "google",
    externalId,
    email: normalizeEmail(data?.email),
    emailVerified: data?.verified_email === true || data?.verified_email === "true",
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
    grantedScopes: meta.grantedScopes || []
  };
};
var exchangeGoogleCode = async (code, redirectUri) => {
  const config = getGoogleConfig();
  const body = new URLSearchParams({
    code,
    client_id: config.clientId,
    client_secret: config.clientSecret,
    redirect_uri: redirectUri,
    grant_type: "authorization_code"
  });
  const { data } = await fetchJson("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json"
    },
    body
  });
  const accessToken = getString(data?.access_token);
  if (!accessToken)
    throw new Error("OAUTH_INVALID_TOKEN");
  return getGoogleUserFromAccessToken(accessToken, {
    accessTokenExpiresIn: Number.isFinite(Number(data?.expires_in)) ? Number(data.expires_in) : null,
    refreshToken: getString(data?.refresh_token),
    refreshTokenExpiresIn: Number.isFinite(Number(data?.refresh_token_expires_in)) ? Number(data.refresh_token_expires_in) : null,
    grantedScopes: splitScopes(getString(data?.scope) || undefined, [])
  });
};
var getGithubEmails = async (accessToken) => {
  const { data } = await fetchJson("https://api.github.com/user/emails", {
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${accessToken}`,
      "User-Agent": "the-api-users",
      "X-GitHub-Api-Version": GITHUB_API_VERSION
    }
  });
  const emails = Array.isArray(data) ? data : [];
  const primary = emails.find((item) => item?.primary === true) || emails.find((item) => item?.verified === true) || emails.find((item) => typeof item?.email === "string");
  return {
    email: normalizeEmail(primary?.email),
    verified: !!primary?.verified
  };
};
var getGithubUserFromAccessToken = async (accessToken, meta = {}) => {
  const { data, response } = await fetchJson("https://api.github.com/user", {
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${accessToken}`,
      "User-Agent": "the-api-users",
      "X-GitHub-Api-Version": GITHUB_API_VERSION
    }
  });
  const externalId = getString(data?.id);
  if (!externalId)
    throw new Error("OAUTH_INVALID_TOKEN");
  const emailInfo = await getGithubEmails(accessToken);
  const grantedScopes = meta.grantedScopes || splitScopes(response.headers.get("x-oauth-scopes") || undefined, []);
  return {
    service: "github",
    externalId,
    email: normalizeEmail(data?.email) || emailInfo.email,
    emailVerified: emailInfo.verified,
    fullName: getString(data?.name),
    username: getString(data?.login),
    avatar: getString(data?.avatar_url),
    locale: null,
    rawProfile: {
      ...data,
      emails: emailInfo.email ? [emailInfo.email] : []
    },
    accessToken,
    accessTokenExpiresIn: meta.accessTokenExpiresIn ?? null,
    refreshToken: meta.refreshToken ?? null,
    refreshTokenExpiresIn: meta.refreshTokenExpiresIn ?? null,
    grantedScopes
  };
};
var exchangeGithubCode = async (code, redirectUri) => {
  const config = getGithubConfig();
  const body = new URLSearchParams({
    client_id: config.clientId,
    client_secret: config.clientSecret,
    code,
    redirect_uri: redirectUri
  });
  const { data } = await fetchJson("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body
  });
  const accessToken = getString(data?.access_token);
  if (!accessToken)
    throw new Error("OAUTH_INVALID_TOKEN");
  return getGithubUserFromAccessToken(accessToken, {
    accessTokenExpiresIn: Number.isFinite(Number(data?.expires_in)) ? Number(data.expires_in) : null,
    refreshToken: getString(data?.refresh_token),
    refreshTokenExpiresIn: Number.isFinite(Number(data?.refresh_token_expires_in)) ? Number(data.refresh_token_expires_in) : null,
    grantedScopes: splitScopes(getString(data?.scope) || undefined, [])
  });
};
var getFacebookUserFromAccessToken = async (accessToken, meta = {}) => {
  const config = getFacebookConfig();
  const { data } = await fetchJson(`https://graph.facebook.com/${FACEBOOK_API_VERSION}/me?${toQueryString({
    fields: (config.fields || []).join(","),
    access_token: accessToken
  })}`);
  const externalId = getString(data?.id);
  if (!externalId)
    throw new Error("OAUTH_INVALID_TOKEN");
  return {
    service: "facebook",
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
    grantedScopes: meta.grantedScopes || []
  };
};
var exchangeFacebookCode = async (code, redirectUri) => {
  const config = getFacebookConfig();
  const { data } = await fetchJson(`https://graph.facebook.com/${FACEBOOK_API_VERSION}/oauth/access_token?${toQueryString({
    client_id: config.clientId,
    client_secret: config.clientSecret,
    redirect_uri: redirectUri,
    code
  })}`);
  const accessToken = getString(data?.access_token);
  if (!accessToken)
    throw new Error("OAUTH_INVALID_TOKEN");
  return getFacebookUserFromAccessToken(accessToken, {
    accessTokenExpiresIn: Number.isFinite(Number(data?.expires_in)) ? Number(data.expires_in) : null
  });
};
var getLinkedinUserFromAccessToken = async (accessToken, meta = {}) => {
  const { data } = await fetchJson("https://api.linkedin.com/v2/userinfo", {
    headers: {
      Authorization: `Bearer ${accessToken}`
    }
  });
  const externalId = getString(data?.sub);
  if (!externalId)
    throw new Error("OAUTH_INVALID_TOKEN");
  return {
    service: "linkedin",
    externalId,
    email: normalizeEmail(data?.email),
    emailVerified: data?.email_verified === true || data?.email_verified === "true",
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
    grantedScopes: meta.grantedScopes || []
  };
};
var exchangeLinkedinCode = async (code, redirectUri) => {
  const config = getLinkedinConfig();
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    client_id: config.clientId,
    client_secret: config.clientSecret,
    redirect_uri: redirectUri
  });
  const { data } = await fetchJson("https://www.linkedin.com/oauth/v2/accessToken", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body
  });
  const accessToken = getString(data?.access_token);
  if (!accessToken)
    throw new Error("OAUTH_INVALID_TOKEN");
  return getLinkedinUserFromAccessToken(accessToken, {
    accessTokenExpiresIn: Number.isFinite(Number(data?.expires_in)) ? Number(data.expires_in) : null,
    refreshToken: getString(data?.refresh_token),
    refreshTokenExpiresIn: Number.isFinite(Number(data?.refresh_token_expires_in)) ? Number(data.refresh_token_expires_in) : null,
    grantedScopes: splitScopes(getString(data?.scope) || undefined, [])
  });
};
var getTwitterUserFromAccessToken = async (accessToken, meta = {}) => {
  const config = getTwitterConfig();
  const { data } = await fetchJson(`https://api.twitter.com/2/users/me?${toQueryString({
    "user.fields": (config.fields || []).join(",")
  })}`, {
    headers: {
      Authorization: `Bearer ${accessToken}`
    }
  });
  const userData = data?.data || data;
  const externalId = getString(userData?.id);
  if (!externalId)
    throw new Error("OAUTH_INVALID_TOKEN");
  return {
    service: "twitter",
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
    grantedScopes: meta.grantedScopes || []
  };
};
var exchangeTwitterCode = async (code, redirectUri, codeVerifier) => {
  const config = getTwitterConfig();
  const body = new URLSearchParams({
    code,
    grant_type: "authorization_code",
    client_id: config.clientId,
    redirect_uri: redirectUri,
    code_verifier: codeVerifier
  });
  const { data } = await fetchJson("https://api.twitter.com/2/oauth2/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${Buffer.from(`${encodeURIComponent(config.clientId)}:${encodeURIComponent(config.clientSecret)}`).toString("base64")}`
    },
    body
  });
  const accessToken = getString(data?.access_token);
  if (!accessToken)
    throw new Error("OAUTH_INVALID_TOKEN");
  return getTwitterUserFromAccessToken(accessToken, {
    accessTokenExpiresIn: Number.isFinite(Number(data?.expires_in)) ? Number(data.expires_in) : null,
    refreshToken: getString(data?.refresh_token),
    refreshTokenExpiresIn: null,
    grantedScopes: splitScopes(getString(data?.scope) || undefined, [])
  });
};
var getMicrosoftUserFromAccessToken = async (accessToken, meta = {}) => {
  const { data } = await fetchJson("https://graph.microsoft.com/v1.0/me?$select=id,displayName,givenName,surname,mail,userPrincipalName", {
    headers: {
      Authorization: `Bearer ${accessToken}`
    }
  });
  const externalId = getString(data?.id);
  if (!externalId)
    throw new Error("OAUTH_INVALID_TOKEN");
  const email = normalizeEmail(data?.mail) || normalizeEmail(data?.userPrincipalName);
  return {
    service: "microsoft",
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
    grantedScopes: meta.grantedScopes || []
  };
};
var exchangeMicrosoftCode = async (code, redirectUri) => {
  const config = getMicrosoftConfig();
  const body = new URLSearchParams({
    client_id: config.clientId,
    client_secret: config.clientSecret,
    redirect_uri: redirectUri,
    code,
    grant_type: "authorization_code"
  });
  const { data } = await fetchJson(`https://login.microsoftonline.com/${config.tenantId}/oauth2/v2.0/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body
  });
  const accessToken = getString(data?.access_token);
  if (!accessToken)
    throw new Error("OAUTH_INVALID_TOKEN");
  return getMicrosoftUserFromAccessToken(accessToken, {
    accessTokenExpiresIn: Number.isFinite(Number(data?.expires_in)) ? Number(data.expires_in) : null,
    refreshToken: getString(data?.refresh_token),
    refreshTokenExpiresIn: null,
    grantedScopes: splitScopes(getString(data?.scope) || undefined, [])
  });
};
var getAppleJwks = async () => {
  const { data } = await fetchJson("https://appleid.apple.com/auth/keys");
  return Array.isArray(data?.keys) ? data.keys : [];
};
var verifyAppleIdToken = async (idToken, extraUser) => {
  const decoded = decodeJwt(idToken);
  const config = getAppleConfig();
  const now = Math.floor(Date.now() / 1000);
  if (decoded.header.alg !== "RS256" || !decoded.header.kid) {
    throw new Error("OAUTH_INVALID_TOKEN");
  }
  const keys = await getAppleJwks();
  const jwk = keys.find((key) => key?.kid === decoded.header.kid && key?.kty === "RSA");
  if (!jwk)
    throw new Error("OAUTH_INVALID_TOKEN");
  const isValid = cryptoVerify("RSA-SHA256", Buffer.from(decoded.signingInput), createPublicKey({ key: jwk, format: "jwk" }), decoded.signature);
  if (!isValid)
    throw new Error("OAUTH_INVALID_TOKEN");
  if (decoded.payload.iss !== APPLE_AUDIENCE)
    throw new Error("OAUTH_INVALID_TOKEN");
  if (decoded.payload.aud !== config.clientId)
    throw new Error("OAUTH_INVALID_TOKEN");
  if (!decoded.payload.exp || Number(decoded.payload.exp) <= now)
    throw new Error("OAUTH_INVALID_TOKEN");
  const extra = typeof extraUser === "string" ? parseJson(extraUser) : extraUser && typeof extraUser === "object" ? extraUser : null;
  const parsedName = extra?.name || {};
  const email = normalizeEmail(decoded.payload.email);
  const externalId = getString(decoded.payload.sub);
  if (!externalId)
    throw new Error("OAUTH_INVALID_TOKEN");
  const givenName = getString(parsedName?.firstName);
  const familyName = getString(parsedName?.lastName);
  const fullName = [givenName, familyName].filter(Boolean).join(" ") || getString(extra?.fullName);
  return {
    service: "apple",
    externalId,
    email,
    emailVerified: decoded.payload.email_verified === true || decoded.payload.email_verified === "true",
    fullName: fullName || null,
    givenName,
    familyName,
    avatar: null,
    locale: null,
    rawProfile: {
      ...decoded.payload,
      user: extra || undefined
    },
    accessToken: null,
    accessTokenExpiresIn: null,
    refreshToken: null,
    refreshTokenExpiresIn: null,
    grantedScopes: splitScopes(getString(decoded.payload.scope) || undefined, [])
  };
};
var exchangeAppleCode = async (code, redirectUri, extraUser) => {
  const config = getAppleConfig();
  const body = new URLSearchParams({
    client_id: config.clientId,
    client_secret: config.clientSecret,
    code,
    grant_type: "authorization_code",
    redirect_uri: redirectUri
  });
  const { data } = await fetchJson("https://appleid.apple.com/auth/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body
  });
  const idToken = getString(data?.id_token);
  if (!idToken)
    throw new Error("OAUTH_INVALID_TOKEN");
  const identity = await verifyAppleIdToken(idToken, extraUser);
  return {
    ...identity,
    accessToken: getString(data?.access_token),
    accessTokenExpiresIn: Number.isFinite(Number(data?.expires_in)) ? Number(data.expires_in) : null,
    refreshToken: getString(data?.refresh_token),
    refreshTokenExpiresIn: null
  };
};
var getOAuthAuthorizationUrl = (serviceName, stateOverride) => {
  const service = ensureService(serviceName);
  const state = stateOverride || createOAuthState();
  const config = getServiceConfig(service);
  if (service === "google") {
    const url2 = `https://accounts.google.com/o/oauth2/v2/auth?${toQueryString({
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      response_type: "code",
      scope: config.scope.join(" "),
      state,
      include_granted_scopes: "true",
      access_type: getString(process.env.AUTH_GOOGLE_ACCESS_TYPE) || "offline",
      prompt: getString(process.env.AUTH_GOOGLE_PROMPT) || undefined
    })}`;
    return { service, state, url: url2 };
  }
  if (service === "apple") {
    const url2 = `https://appleid.apple.com/auth/authorize?${toQueryString({
      response_type: "code",
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      scope: config.scope.join(" "),
      state,
      response_mode: "form_post"
    })}`;
    return { service, state, url: url2 };
  }
  if (service === "github") {
    const url2 = `https://github.com/login/oauth/authorize?${toQueryString({
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      scope: config.scope.join(" "),
      state
    })}`;
    return { service, state, url: url2 };
  }
  if (service === "facebook") {
    const url2 = `https://www.facebook.com/${FACEBOOK_API_VERSION}/dialog/oauth?${toQueryString({
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      response_type: "code",
      scope: config.scope.join(","),
      state
    })}`;
    return { service, state, url: url2 };
  }
  if (service === "linkedin") {
    const url2 = `https://www.linkedin.com/oauth/v2/authorization?${toQueryString({
      response_type: "code",
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      scope: config.scope.join(" "),
      state
    })}`;
    return { service, state, url: url2 };
  }
  if (service === "microsoft") {
    const url2 = `https://login.microsoftonline.com/${config.tenantId}/oauth2/v2.0/authorize?${toQueryString({
      response_type: "code",
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      scope: config.scope.join(" "),
      include_granted_scopes: "true",
      state
    })}`;
    return { service, state, url: url2 };
  }
  const codeVerifier = createCodeVerifier();
  const codeChallenge = createCodeChallenge(codeVerifier);
  const url = `https://x.com/i/oauth2/authorize?${toQueryString({
    response_type: "code",
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    scope: config.scope.join(" "),
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256"
  })}`;
  return { service, state, url, codeVerifier };
};
var isOAuthServiceConfigured = (serviceName) => {
  const service = ensureService(serviceName);
  try {
    getServiceConfig(service);
    return true;
  } catch (error) {
    if (error instanceof Error && error.message === "OAUTH_CONFIG_NOT_FOUND") {
      return false;
    }
    throw error;
  }
};
var rememberOAuthState = (c, service, state) => {
  setOAuthStateCookie(c, service, state);
};
var rememberOAuthCodeVerifier = (c, service, codeVerifier) => {
  setOAuthTempCookie(c, service, "code_verifier", codeVerifier);
};
var getOAuthCodeVerifier = (c, service) => getCookie(c, getOAuthTempCookieName(service, "code_verifier")) || null;
var clearOAuthCodeVerifier = (c, service) => {
  setCookie(c, getOAuthTempCookieName(service, "code_verifier"), "", {
    httpOnly: true,
    path: "/",
    sameSite: "Lax",
    secure: c.req.url.startsWith("https://"),
    maxAge: 0
  });
};
var resolveOAuthIdentity = async (serviceName, payload) => {
  const service = ensureService(serviceName);
  const config = getServiceConfig(service);
  const redirectUri = getString(payload.redirectUri) || config.redirectUri;
  if (config.redirectUri && redirectUri !== config.redirectUri) {
    throw new Error("OAUTH_INVALID_REDIRECT_URI");
  }
  const code = getString(payload.code);
  const accessToken = getString(payload.accessToken);
  const idToken = getString(payload.idToken);
  const codeVerifier = getString(payload.codeVerifier);
  const user = payload.user;
  if (service === "apple") {
    if (code)
      return exchangeAppleCode(code, redirectUri, user);
    if (idToken)
      return verifyAppleIdToken(idToken, user);
    throw new Error("OAUTH_TOKEN_REQUIRED");
  }
  if (service === "google") {
    if (code)
      return exchangeGoogleCode(code, redirectUri);
    if (accessToken)
      return getGoogleUserFromAccessToken(accessToken);
    if (idToken)
      return verifyGoogleIdToken(idToken);
    throw new Error("OAUTH_TOKEN_REQUIRED");
  }
  if (service === "github") {
    if (code)
      return exchangeGithubCode(code, redirectUri);
    if (accessToken)
      return getGithubUserFromAccessToken(accessToken);
    throw new Error("OAUTH_TOKEN_REQUIRED");
  }
  if (service === "facebook") {
    if (code)
      return exchangeFacebookCode(code, redirectUri);
    if (accessToken)
      return getFacebookUserFromAccessToken(accessToken);
    throw new Error("OAUTH_TOKEN_REQUIRED");
  }
  if (service === "linkedin") {
    if (code)
      return exchangeLinkedinCode(code, redirectUri);
    if (accessToken)
      return getLinkedinUserFromAccessToken(accessToken);
    throw new Error("OAUTH_TOKEN_REQUIRED");
  }
  if (service === "microsoft") {
    if (code)
      return exchangeMicrosoftCode(code, redirectUri);
    if (accessToken)
      return getMicrosoftUserFromAccessToken(accessToken);
    throw new Error("OAUTH_TOKEN_REQUIRED");
  }
  if (code) {
    if (!codeVerifier)
      throw new Error("OAUTH_INVALID_TOKEN");
    return exchangeTwitterCode(code, redirectUri, codeVerifier);
  }
  if (accessToken)
    return getTwitterUserFromAccessToken(accessToken);
  throw new Error("OAUTH_TOKEN_REQUIRED");
};
var parseProviders = (value) => {
  if (!value)
    return {};
  if (typeof value === "string") {
    try {
      return parseProviders(JSON.parse(value));
    } catch {
      return {};
    }
  }
  if (typeof value !== "object" || Array.isArray(value))
    return {};
  const result = {};
  for (const service of OAUTH_SERVICES) {
    const record = value[service];
    if (record && typeof record === "object" && !Array.isArray(record)) {
      result[service] = record;
    }
  }
  return result;
};
var normalizeOAuthProviders = (value) => parseProviders(value);
var getOAuthServices = (value) => OAUTH_SERVICES.filter((service) => !!normalizeOAuthProviders(value)[service]);
var getOAuthServiceSummaries = (value) => {
  const providers = normalizeOAuthProviders(value);
  return OAUTH_SERVICES.map((service) => providers[service]).filter(Boolean).map((provider) => ({
    service: provider.service,
    email: provider.email,
    phone: provider.phone,
    fullName: provider.fullName,
    avatar: provider.avatar,
    linkedAt: provider.linkedAt,
    updatedAt: provider.updatedAt
  }));
};
var buildOAuthProviderRecord = (identity, linkedAt) => ({
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
  profile: identity.rawProfile
});
var withOAuthProvider = (value, identity) => {
  const providers = normalizeOAuthProviders(value);
  const existing = providers[identity.service];
  return {
    ...providers,
    [identity.service]: buildOAuthProviderRecord(identity, existing?.linkedAt)
  };
};
var withoutOAuthProvider = (value, serviceName) => {
  const service = ensureService(serviceName);
  const providers = normalizeOAuthProviders(value);
  const nextProviders = { ...providers };
  delete nextProviders[service];
  return nextProviders;
};
var findUserByOAuthService = async (c, serviceName, externalId) => {
  const service = ensureService(serviceName);
  const db = getDb(c);
  const clientName = String(db.client.config.client || "");
  if (clientName.includes("pg")) {
    return db("users").whereRaw(`("oauthProviders" -> ?) ->> 'externalId' = ?`, [service, externalId]).first();
  }
  const users = await db("users").whereNotNull("oauthProviders").select("*");
  return users.find((user) => normalizeOAuthProviders(user.oauthProviders)[service]?.externalId === externalId);
};

// src/lib/user-config.ts
var USER_HIDDEN_FIELDS = [
  "password",
  "salt",
  "refresh",
  "timeRefreshExpired",
  "registerCode",
  "registerCodeAttempts",
  "timeRegisterCodeExpired",
  "recoverCode",
  "recoverCodeAttempts",
  "timeRecoverCodeExpired",
  "phoneCode",
  "phoneCodeAttempts",
  "timePhoneCodeExpired",
  "phoneChangeCode",
  "phoneChangeCodeAttempts",
  "timePhoneChangeCodeExpired",
  "phoneToChange",
  "emailChangeCode",
  "emailChangeCodeAttempts",
  "timeEmailChangeCodeExpired",
  "emailToChange",
  "oauthProviders",
  "email",
  "phone"
];
var USER_VISIBLE_FOR = {
  "users.viewEmail": ["email", "isEmailVerified"],
  "users.viewPhone": ["phone", "isPhoneVerified"],
  "users.viewRole": ["role"],
  "users.viewLocale": ["locale", "timezone"],
  "users.viewStatus": ["isBlocked", "isDeleted", "isEmailInvalid", "isPhoneInvalid"],
  "users.viewMeta": ["timeCreated", "timeUpdated", "timeDeleted"]
};
var USER_OWNER_PERMISSIONS = [
  "users.viewEmail",
  "users.viewPhone",
  "users.viewRole",
  "users.viewLocale",
  "users.viewMeta"
];
var USER_EDITABLE_FOR = {
  "users.editProfile": ["fullName", "locale", "timezone"],
  "users.editEmail": ["email"],
  "users.editPhone": ["phone"],
  "users.editRole": ["role"],
  "users.editStatus": ["isBlocked", "isDeleted", "isEmailInvalid", "isPhoneInvalid"],
  "users.editVerification": ["isEmailVerified", "isPhoneVerified"]
};
var USER_SELF_EDITABLE_FIELDS = ["fullName", "locale", "timezone"];

// src/modules/login.ts
var login = new Routings;
var CODE_EXPIRES_IN = process.env.AUTH_CODE_EXPIRES_IN || "30m";
var RECOVER_CODE_EXPIRES_IN = process.env.AUTH_RECOVER_CODE_EXPIRES_IN || CODE_EXPIRES_IN;
var REFRESH_EXPIRES_IN = process.env.AUTH_REFRESH_EXPIRES_IN || "30d";
var VERIFIED_ROLE2 = process.env.AUTH_VERIFIED_ROLE || process.env.AUTH_DEFAULT_ROLE || "registered";
var UNVERIFIED_ROLE2 = process.env.AUTH_UNVERIFIED_ROLE || "unverified";
var REQUIRE_EMAIL_VERIFICATION = process.env.AUTH_REQUIRE_EMAIL_VERIFICATION === "true";
var MAX_CODE_ATTEMPTS = Number(process.env.AUTH_MAX_CODE_ATTEMPTS || 5);
var LOGIN_ERRORS = {
  USER_NOT_FOUND: {
    code: 101,
    status: 404,
    description: "User not found"
  },
  USER_ACCESS_DENIED: {
    code: 102,
    status: 403,
    description: "User access denied"
  },
  EMAIL_EXISTS: {
    code: 103,
    status: 409,
    description: "Email already exists"
  },
  PHONE_EXISTS: {
    code: 104,
    status: 409,
    description: "Phone already exists"
  },
  LOGIN_EXISTS: {
    code: 105,
    status: 409,
    description: "Login already exists"
  },
  EMAIL_NOT_CONFIRMED: {
    code: 106,
    status: 403,
    description: "Email is not confirmed"
  },
  INVALID_OR_EXPIRED_CODE: {
    code: 107,
    status: 409,
    description: "Code is invalid or expired"
  },
  WRONG_CODE: {
    code: 108,
    status: 409,
    description: "Wrong code"
  },
  WRONG_PASSWORD: {
    code: 109,
    status: 409,
    description: "Wrong password"
  },
  NO_TOKEN: {
    code: 110,
    status: 401,
    description: "Token required"
  },
  INVALID_EMAIL: {
    code: 111,
    status: 400,
    description: "Email is invalid"
  },
  INVALID_PHONE: {
    code: 112,
    status: 400,
    description: "Phone is invalid"
  },
  PASSWORD_REQUIRED: {
    code: 113,
    status: 400,
    description: "Password is required"
  },
  LOGIN_OR_EMAIL_REQUIRED: {
    code: 114,
    status: 400,
    description: "Login or email is required"
  },
  NOTHING_TO_CONFIRM: {
    code: 115,
    status: 409,
    description: "Nothing to confirm"
  },
  EMAIL_ALREADY_CONFIRMED: {
    code: 116,
    status: 409,
    description: "Email is already confirmed"
  },
  SMS_SEND_FAILED: {
    code: 117,
    status: 502,
    description: "SMS provider failed to deliver the message"
  },
  OAUTH_SERVICE_NOT_SUPPORTED: {
    code: 118,
    status: 404,
    description: "OAuth service is not supported"
  },
  OAUTH_CONFIG_NOT_FOUND: {
    code: 119,
    status: 404,
    description: "OAuth configuration not found"
  },
  OAUTH_TOKEN_REQUIRED: {
    code: 120,
    status: 400,
    description: "OAuth code or token is required"
  },
  OAUTH_INVALID_TOKEN: {
    code: 121,
    status: 401,
    description: "OAuth token is invalid or expired"
  },
  OAUTH_INVALID_STATE: {
    code: 122,
    status: 401,
    description: "OAuth state is invalid"
  },
  OAUTH_CONFLICT: {
    code: 123,
    status: 409,
    description: "OAuth identity belongs to another user"
  },
  OAUTH_IDENTITY_REQUIRED: {
    code: 124,
    status: 400,
    description: "OAuth provider did not return an email or phone"
  },
  OAUTH_INVALID_REDIRECT_URI: {
    code: 125,
    status: 400,
    description: "OAuth redirect URI is invalid"
  },
  OAUTH_LAST_LOGIN_METHOD: {
    code: 126,
    status: 409,
    description: "Cannot unlink the last available login method"
  }
};
var AUTH_EMAIL_TEMPLATES = {
  login_register_code: {
    subject: "Confirm your email",
    text: "Use this code to confirm your email: {{code}}"
  },
  login_recover_code: {
    subject: "Password recovery code",
    text: "Use this code to restore your password: {{code}}"
  },
  login_email_change_code: {
    subject: "Confirm your new email",
    text: "Use this code to confirm your new email: {{code}}"
  }
};
var getRoleAfterVerifiedIdentity = (role) => role === UNVERIFIED_ROLE2 || !role ? VERIFIED_ROLE2 : role;
var trimString = (value) => {
  if (typeof value !== "string")
    return null;
  const result = value.trim();
  return result || null;
};
var toPublicAuthUser = (user) => ({
  id: user.id,
  email: user.email || null,
  phone: user.phone || null,
  fullName: user.fullName || null,
  role: user.role || (isUserIdentityVerified(user) ? VERIFIED_ROLE2 : UNVERIFIED_ROLE2),
  roles: getUserRoles(user),
  avatar: user.avatar || null,
  locale: user.locale || null,
  timezone: user.timezone || null,
  isEmailVerified: !!user.isEmailVerified,
  isPhoneVerified: !!user.isPhoneVerified,
  oauthServices: getOAuthServices(user.oauthProviders)
});
var findUserByEmail = async (c, email) => {
  const db = getDb(c);
  return db("users").whereRaw("LOWER(email) = ?", [email]).first();
};
var findUserByLogin = async (c, loginName) => {
  const db = getDb(c);
  return db("users").whereRaw("LOWER(login) = ?", [loginName.toLowerCase()]).first();
};
var findUserByPhone = async (c, phone) => {
  const db = getDb(c);
  return db("users").where({ phone }).first();
};
var findUserByRefresh = async (c, refresh) => {
  const db = getDb(c);
  return db("users").where({ refresh }).first();
};
var findUserByRecoverCode = async (c, code) => {
  const db = getDb(c);
  return db("users").where({ recoverCode: code }).first();
};
var assertUserActive = (user) => {
  if (!user || user.isDeleted)
    throw new Error("USER_NOT_FOUND");
  if (user.isBlocked)
    throw new Error("USER_ACCESS_DENIED");
  return user;
};
var ensureEmailUnique = async (c, email, exceptUserId) => {
  const db = getDb(c);
  const query = db("users").whereRaw("LOWER(email) = ?", [email]);
  if (exceptUserId)
    query.whereNot({ id: exceptUserId });
  const existing = await query.first();
  if (existing)
    throw new Error("EMAIL_EXISTS");
};
var ensurePhoneUnique = async (c, phone, exceptUserId) => {
  const db = getDb(c);
  const query = db("users").where({ phone });
  if (exceptUserId)
    query.whereNot({ id: exceptUserId });
  const existing = await query.first();
  if (existing)
    throw new Error("PHONE_EXISTS");
};
var ensureLoginUnique = async (c, loginName, exceptUserId) => {
  const db = getDb(c);
  const query = db("users").whereRaw("LOWER(login) = ?", [loginName.toLowerCase()]);
  if (exceptUserId)
    query.whereNot({ id: exceptUserId });
  const existing = await query.first();
  if (existing)
    throw new Error("LOGIN_EXISTS");
};
var getRandomOAuthLoginNumber = () => Math.floor(Math.random() * 9999) + 1;
var MAX_OAUTH_LOGIN_ATTEMPTS = 100;
var getOAuthLoginBase = (identityValue) => identityValue.split("@")[0] || identityValue;
var formatOAuthLogin = (base, number) => {
  const suffix = String(number);
  return `${base.slice(0, Math.max(0, 255 - suffix.length))}${suffix}`;
};
var createUniqueOAuthLogin = async (c, identityValue) => {
  const base = getOAuthLoginBase(identityValue);
  let number = getRandomOAuthLoginNumber();
  let attempts = 0;
  while (attempts < MAX_OAUTH_LOGIN_ATTEMPTS) {
    attempts += 1;
    const loginName = formatOAuthLogin(base, number);
    const existing = await findUserByLogin(c, loginName);
    if (!existing)
      return loginName;
    number += getRandomOAuthLoginNumber();
  }
  throw new Error("LOGIN_EXISTS");
};
var saveAuthResult = async (c, user, refreshOverride) => {
  const dbWrite = getDbWrite(c);
  const refresh = refreshOverride || (!isExpired(user.timeRefreshExpired) ? user.refresh : undefined) || randomToken();
  const timeRefreshExpired = getExpiresAt(REFRESH_EXPIRES_IN, 30 * 24 * 60 * 60);
  await dbWrite("users").where({ id: user.id }).update({
    refresh,
    timeRefreshExpired,
    timeUpdated: dbWrite.fn.now()
  });
  const token = signJwt({
    id: user.id,
    role: user.role || (isUserIdentityVerified(user) ? VERIFIED_ROLE2 : UNVERIFIED_ROLE2),
    roles: getUserRoles(user),
    email: user.email || undefined,
    phone: user.phone || undefined,
    fullName: user.fullName || undefined
  });
  c.set("result", {
    ...toPublicAuthUser(user),
    token,
    refresh
  });
};
var setCode = async (c, userId, {
  codeField,
  attemptsField,
  expiresField,
  code,
  expiresAt,
  extra = {}
}) => {
  const dbWrite = getDbWrite(c);
  await dbWrite("users").where({ id: userId }).update({
    [codeField]: code,
    [attemptsField]: 0,
    [expiresField]: expiresAt,
    ...extra,
    timeUpdated: dbWrite.fn.now()
  });
};
var clearCode = async (c, userId, {
  codeField,
  attemptsField,
  expiresField,
  extra = {}
}) => {
  const dbWrite = getDbWrite(c);
  await dbWrite("users").where({ id: userId }).update({
    [codeField]: null,
    [attemptsField]: 0,
    [expiresField]: null,
    ...extra,
    timeUpdated: dbWrite.fn.now()
  });
};
var failCodeAttempt = async (c, user, attemptsField, errorName = "INVALID_OR_EXPIRED_CODE") => {
  if (user?.id) {
    const dbWrite = getDbWrite(c);
    await dbWrite("users").where({ id: user.id }).update({
      [attemptsField]: Math.min(MAX_CODE_ATTEMPTS, Number(user[attemptsField] || 0) + 1),
      timeUpdated: dbWrite.fn.now()
    });
  }
  throw new Error(errorName);
};
var verifyStoredCode = async (c, user, {
  code,
  codeField,
  attemptsField,
  expiresField,
  errorName = "INVALID_OR_EXPIRED_CODE"
}) => {
  if (!user) {
    throw new Error(errorName);
  }
  const savedCode = trimString(user[codeField]);
  const attempts = Number(user[attemptsField] || 0);
  const expiresAt = user[expiresField];
  if (!savedCode || attempts >= MAX_CODE_ATTEMPTS || isExpired(expiresAt) || savedCode !== code) {
    await failCodeAttempt(c, user, attemptsField, errorName);
  }
  return user;
};
var sendRegisterCode = async (c, user, code) => {
  if (!user.email)
    return;
  await sendEmail(c, {
    to: user.email,
    template: "login_register_code",
    data: { code, email: user.email, fullName: user.fullName || "" }
  });
};
var sendRecoverCode = async (c, user, code) => {
  if (!user.email)
    return;
  await sendEmail(c, {
    to: user.email,
    template: "login_recover_code",
    data: { code, email: user.email, fullName: user.fullName || "" }
  });
};
var sendEmailChangeCode = async (c, email, user, code) => {
  await sendEmail(c, {
    to: email,
    template: "login_email_change_code",
    data: { code, email, fullName: user.fullName || "" }
  });
};
var sendPhoneConfirmationCode = async (c, phone, code) => {
  await sendSms(c, {
    to: phone,
    body: `Your confirmation code is ${code}`
  });
};
var getCurrentUserRecord = async (c) => {
  const authUser = requireAuth(c);
  const db = getDb(c);
  const user = await db("users").where({ id: authUser.id }).first();
  return assertUserActive(user);
};
var getBodyObject = (c) => c.var.body && typeof c.var.body === "object" && !Array.isArray(c.var.body) ? c.var.body : {};
var getConfirmationPayload = async (c, target) => {
  const user = await getCurrentUserRecord(c);
  const code = trimString(getBodyObject(c).code);
  if (!code)
    throw new Error("INVALID_OR_EXPIRED_CODE");
  return { user, code };
};
var getOptionalCurrentUserRecord = async (c) => {
  const authUser = getRequestUser(c);
  if (!authUser.id || !Array.isArray(authUser.roles) || authUser.roles.includes("guest")) {
    return;
  }
  const db = getDb(c);
  const user = await db("users").where({ id: authUser.id }).first();
  return assertUserActive(user);
};
var shouldRequireVerifiedIdentity = (user) => REQUIRE_EMAIL_VERIFICATION && !isUserIdentityVerified(user);
var chooseOAuthTargetUser = ({
  currentUser,
  userByService,
  userByEmail,
  userByPhone
}) => {
  const candidates = [userByService, userByEmail, userByPhone].filter(Boolean);
  if (currentUser) {
    for (const candidate of candidates) {
      if (candidate.id !== currentUser.id)
        throw new Error("OAUTH_CONFLICT");
    }
    return currentUser;
  }
  const uniqueCandidates = new Map;
  for (const candidate of candidates)
    uniqueCandidates.set(candidate.id, candidate);
  if (uniqueCandidates.size > 1)
    throw new Error("OAUTH_CONFLICT");
  return Array.from(uniqueCandidates.values())[0];
};
var createOAuthUser = async (c, identity) => {
  const dbWrite = getDbWrite(c);
  const email = identity.email || null;
  const phone = identity.phone ? normalizePhone(identity.phone) : null;
  const identityValue = email || phone;
  if (!identityValue)
    throw new Error("OAUTH_IDENTITY_REQUIRED");
  if (email)
    await ensureEmailUnique(c, email);
  if (phone)
    await ensurePhoneUnique(c, phone);
  const loginName = await createUniqueOAuthLogin(c, identityValue);
  const [user] = await dbWrite("users").insert({
    login: loginName,
    email,
    isEmailVerified: !!email,
    phone,
    isPhoneVerified: !!phone,
    fullName: identity.fullName || null,
    avatar: identity.avatar || null,
    locale: identity.locale || null,
    password: null,
    salt: null,
    role: getRoleAfterVerifiedIdentity(null),
    refresh: randomToken(),
    timeRefreshExpired: getExpiresAt(REFRESH_EXPIRES_IN, 30 * 24 * 60 * 60),
    oauthProviders: withOAuthProvider(null, identity)
  }).returning("*");
  return user;
};
var syncUserWithOAuthIdentity = async (c, user, identity) => {
  const dbWrite = getDbWrite(c);
  const email = identity.email || null;
  const phone = identity.phone ? normalizePhone(identity.phone) : null;
  const updates = {
    oauthProviders: withOAuthProvider(user.oauthProviders, identity)
  };
  if (identity.fullName && !user.fullName)
    updates.fullName = identity.fullName;
  if (identity.avatar && !user.avatar)
    updates.avatar = identity.avatar;
  if (identity.locale && !user.locale)
    updates.locale = identity.locale;
  if (email && !user.email) {
    await ensureEmailUnique(c, email, user.id);
    updates.email = email;
    updates.isEmailVerified = true;
  } else if (email && user.email && user.email === email && !user.isEmailVerified) {
    updates.isEmailVerified = true;
  }
  if (phone && !user.phone) {
    await ensurePhoneUnique(c, phone, user.id);
    updates.phone = phone;
    updates.isPhoneVerified = true;
  } else if (phone && user.phone && user.phone === phone && !user.isPhoneVerified) {
    updates.isPhoneVerified = true;
  }
  if (email || phone) {
    updates.role = getRoleAfterVerifiedIdentity(user.role);
  }
  if (!Object.keys(updates).length)
    return user;
  await dbWrite("users").where({ id: user.id }).update({
    ...updates,
    timeUpdated: dbWrite.fn.now()
  });
  return {
    ...user,
    ...updates
  };
};
var getOAuthBody = (c) => getBodyObject(c);
var registerOAuthRoutes = (service) => {
  login.get(`/login/${service}`, async (c) => {
    if (!isOAuthServiceConfigured(service)) {
      throw new Error("OAUTH_SERVICE_NOT_SUPPORTED");
    }
    const { state, url, codeVerifier } = getOAuthAuthorizationUrl(service);
    rememberOAuthState(c, service, state);
    if (codeVerifier)
      rememberOAuthCodeVerifier(c, service, codeVerifier);
    return c.redirect(url);
  });
  login.post(`/login/${service}`, async (c) => {
    if (!isOAuthServiceConfigured(service)) {
      throw new Error("OAUTH_SERVICE_NOT_SUPPORTED");
    }
    const body = getOAuthBody(c);
    const state = trimString(body.state);
    if (!validateOAuthState(c, service, state)) {
      throw new Error("OAUTH_INVALID_STATE");
    }
    const identity = await resolveOAuthIdentity(service, {
      code: trimString(body.code),
      accessToken: trimString(body.accessToken ?? body.access_token ?? body.token),
      idToken: trimString(body.idToken ?? body.id_token),
      redirectUri: trimString(body.redirectUri ?? body.redirect_uri),
      codeVerifier: trimString(body.codeVerifier ?? body.code_verifier) || getOAuthCodeVerifier(c, service),
      user: body.user
    });
    clearOAuthCodeVerifier(c, service);
    const currentUser = await getOptionalCurrentUserRecord(c);
    const userByService = await findUserByOAuthService(c, service, identity.externalId);
    const userByEmail = identity.email ? await findUserByEmail(c, identity.email) : undefined;
    const providerPhone = identity.phone ? normalizePhone(identity.phone) : null;
    const userByPhone = providerPhone ? await findUserByPhone(c, providerPhone) : undefined;
    let user = chooseOAuthTargetUser({
      currentUser,
      userByService: userByService ? assertUserActive(userByService) : undefined,
      userByEmail: userByEmail ? assertUserActive(userByEmail) : undefined,
      userByPhone: userByPhone ? assertUserActive(userByPhone) : undefined
    });
    const normalizedIdentity = {
      ...identity,
      phone: providerPhone,
      emailVerified: !!identity.email,
      phoneVerified: !!providerPhone
    };
    if (!user) {
      user = await createOAuthUser(c, normalizedIdentity);
    } else {
      user = await syncUserWithOAuthIdentity(c, user, normalizedIdentity);
    }
    await saveAuthResult(c, user, !isExpired(user.timeRefreshExpired) ? user.refresh || undefined : undefined);
  });
  login.delete(`/login/${service}`, async (c) => {
    const user = await getCurrentUserRecord(c);
    const providers = normalizeOAuthProviders(user.oauthProviders);
    const linkedServices = getOAuthServices(providers);
    if (!providers[service]) {
      c.set("result", {
        ok: true,
        oauthServices: linkedServices
      });
      return;
    }
    if (!(user.password && user.salt) && linkedServices.length <= 1) {
      throw new Error("OAUTH_LAST_LOGIN_METHOD");
    }
    const nextProviders = withoutOAuthProvider(providers, service);
    const dbWrite = getDbWrite(c);
    await dbWrite("users").where({ id: user.id }).update({
      oauthProviders: nextProviders,
      timeUpdated: dbWrite.fn.now()
    });
    c.set("result", {
      ok: true,
      oauthServices: getOAuthServices(nextProviders)
    });
  });
};
login.errors(LOGIN_ERRORS);
login.emailTemplates(AUTH_EMAIL_TEMPLATES);
login.post("/login/register", async (c) => {
  const body = getBodyObject(c);
  const email = normalizeEmail(body.email);
  const password = trimString(body.password);
  const phone = body.phone === undefined || body.phone === null ? null : normalizePhone(body.phone);
  const loginName = trimString(body.login);
  const fullName = trimString(body.fullName);
  const locale = trimString(body.locale);
  const timezone = trimString(body.timezone);
  if (!email)
    throw new Error("INVALID_EMAIL");
  if (!password)
    throw new Error("PASSWORD_REQUIRED");
  if (body.phone !== undefined && body.phone !== null && !phone)
    throw new Error("INVALID_PHONE");
  await ensureEmailUnique(c, email);
  if (phone)
    await ensurePhoneUnique(c, phone);
  if (loginName)
    await ensureLoginUnique(c, loginName);
  const dbWrite = getDbWrite(c);
  const salt = randomSalt();
  const passwordHash = hashPassword(password, salt);
  const registerCode = REQUIRE_EMAIL_VERIFICATION ? randomCode() : null;
  const timeRegisterCodeExpired = REQUIRE_EMAIL_VERIFICATION ? getExpiresAt(CODE_EXPIRES_IN, 30 * 60) : null;
  const phoneCode = phone ? randomCode() : null;
  const timePhoneCodeExpired = phone ? getExpiresAt(CODE_EXPIRES_IN, 30 * 60) : null;
  const refresh = randomToken();
  const timeRefreshExpired = getExpiresAt(REFRESH_EXPIRES_IN, 30 * 24 * 60 * 60);
  const [user] = await dbWrite("users").insert({
    login: loginName,
    password: passwordHash,
    salt,
    timePasswordChanged: dbWrite.fn.now(),
    email,
    isEmailVerified: !REQUIRE_EMAIL_VERIFICATION,
    phone,
    isPhoneVerified: !phone,
    fullName,
    role: REQUIRE_EMAIL_VERIFICATION ? UNVERIFIED_ROLE2 : VERIFIED_ROLE2,
    locale,
    timezone,
    refresh,
    timeRefreshExpired,
    registerCode,
    registerCodeAttempts: 0,
    timeRegisterCodeExpired,
    phoneCode,
    phoneCodeAttempts: 0,
    timePhoneCodeExpired
  }).returning("*");
  if (registerCode)
    await sendRegisterCode(c, user, registerCode);
  if (phone && phoneCode)
    await sendPhoneConfirmationCode(c, phone, phoneCode);
  if (!REQUIRE_EMAIL_VERIFICATION) {
    await saveAuthResult(c, user);
    return;
  }
  c.set("result", {
    ...toPublicAuthUser(user),
    ok: true,
    refresh,
    emailConfirmationRequired: true,
    phoneConfirmationRequired: !!phone
  });
});
var confirmRegistration = async (c) => {
  const body = getBodyObject(c);
  const email = normalizeEmail(body.email);
  const code = trimString(body.code);
  if (!email || !code)
    throw new Error("INVALID_OR_EXPIRED_CODE");
  const user = assertUserActive(await findUserByEmail(c, email));
  await verifyStoredCode(c, user, {
    code,
    codeField: "registerCode",
    attemptsField: "registerCodeAttempts",
    expiresField: "timeRegisterCodeExpired"
  });
  const dbWrite = getDbWrite(c);
  await dbWrite("users").where({ id: user.id }).update({
    isEmailVerified: true,
    role: getRoleAfterVerifiedIdentity(user.role),
    registerCode: null,
    registerCodeAttempts: 0,
    timeRegisterCodeExpired: null,
    timeUpdated: dbWrite.fn.now()
  });
  const refreshedUser = {
    ...user,
    role: getRoleAfterVerifiedIdentity(user.role),
    isEmailVerified: true,
    registerCode: null,
    registerCodeAttempts: 0,
    timeRegisterCodeExpired: null
  };
  await saveAuthResult(c, refreshedUser);
};
login.post("/login/register/confirm", confirmRegistration);
login.post("/login/register/check", confirmRegistration);
login.post("/login/register/resend", async (c) => {
  const body = getBodyObject(c);
  const email = normalizeEmail(body.email);
  if (!email)
    throw new Error("INVALID_EMAIL");
  const user = assertUserActive(await findUserByEmail(c, email));
  if (user.isEmailVerified)
    throw new Error("EMAIL_ALREADY_CONFIRMED");
  const code = randomCode();
  await setCode(c, user.id, {
    codeField: "registerCode",
    attemptsField: "registerCodeAttempts",
    expiresField: "timeRegisterCodeExpired",
    code,
    expiresAt: getExpiresAt(CODE_EXPIRES_IN, 30 * 60)
  });
  await sendRegisterCode(c, user, code);
  c.set("result", { ok: true });
});
login.post("/login", async (c) => {
  const body = getBodyObject(c);
  const password = trimString(body.password);
  const email = normalizeEmail(body.email ?? body.login);
  const loginName = body.email ? null : trimString(body.login);
  if (!password)
    throw new Error("PASSWORD_REQUIRED");
  if (!email && !loginName)
    throw new Error("LOGIN_OR_EMAIL_REQUIRED");
  const user = assertUserActive(email ? await findUserByEmail(c, email) : await findUserByLogin(c, loginName));
  if (!user.password || !user.salt || !verifyPassword(password, user.salt, user.password)) {
    throw new Error("USER_NOT_FOUND");
  }
  if (shouldRequireVerifiedIdentity(user)) {
    throw new Error("EMAIL_NOT_CONFIRMED");
  }
  await saveAuthResult(c, user, !isExpired(user.timeRefreshExpired) ? user.refresh || undefined : undefined);
});
var refreshHandler = async (c) => {
  const body = c.req.method === "GET" ? {} : getBodyObject(c);
  const refreshQuery = c.var.query?.refresh;
  const refresh = trimString(body.refresh) || trimString(Array.isArray(refreshQuery) ? refreshQuery[0] : refreshQuery);
  if (!refresh)
    throw new Error("USER_NOT_FOUND");
  const user = assertUserActive(await findUserByRefresh(c, refresh));
  if (!user.refresh || user.refresh !== refresh || isExpired(user.timeRefreshExpired)) {
    throw new Error("USER_NOT_FOUND");
  }
  if (shouldRequireVerifiedIdentity(user)) {
    throw new Error("EMAIL_NOT_CONFIRMED");
  }
  await saveAuthResult(c, user, refresh);
};
login.post("/login/refresh", refreshHandler);
login.get("/login/refresh", refreshHandler);
login.post("/login/forgot", async (c) => {
  const body = getBodyObject(c);
  const email = normalizeEmail(body.email ?? body.login);
  const loginName = body.email ? null : trimString(body.login);
  const user = email ? await findUserByEmail(c, email) : loginName ? await findUserByLogin(c, loginName) : undefined;
  if (!user || user.isDeleted || !user.email) {
    c.set("result", { ok: true });
    return;
  }
  const code = randomCode();
  await setCode(c, user.id, {
    codeField: "recoverCode",
    attemptsField: "recoverCodeAttempts",
    expiresField: "timeRecoverCodeExpired",
    code,
    expiresAt: getExpiresAt(RECOVER_CODE_EXPIRES_IN, 30 * 60)
  });
  await sendRecoverCode(c, user, code);
  c.set("result", { ok: true });
});
login.post("/login/restore", async (c) => {
  const body = getBodyObject(c);
  const code = trimString(body.code);
  const password = trimString(body.password);
  if (!code || !password)
    throw new Error("WRONG_CODE");
  const user = await findUserByRecoverCode(c, code);
  await verifyStoredCode(c, user, {
    code,
    codeField: "recoverCode",
    attemptsField: "recoverCodeAttempts",
    expiresField: "timeRecoverCodeExpired",
    errorName: "WRONG_CODE"
  });
  const dbWrite = getDbWrite(c);
  const salt = randomSalt();
  const passwordHash = hashPassword(password, salt);
  await dbWrite("users").where({ id: user.id }).update({
    password: passwordHash,
    salt,
    refresh: randomToken(),
    timeRefreshExpired: new Date(0),
    timePasswordChanged: dbWrite.fn.now(),
    recoverCode: null,
    recoverCodeAttempts: 0,
    timeRecoverCodeExpired: null,
    timeUpdated: dbWrite.fn.now()
  });
  c.set("result", { ok: true });
});
login.patch("/login", async (c) => {
  const authUser = requireAuth(c);
  const body = getBodyObject(c);
  const user = await getCurrentUserRecord(c);
  const dbWrite = getDbWrite(c);
  const updates = {};
  let passwordChanged = false;
  let emailChangeRequested = false;
  let phoneChangeRequested = false;
  for (const field of USER_SELF_EDITABLE_FIELDS) {
    if (body[field] !== undefined) {
      updates[field] = trimString(body[field]);
    }
  }
  const currentPassword = trimString(body.password);
  const newPassword = trimString(body.newPassword);
  if (currentPassword || newPassword) {
    if (!currentPassword || !newPassword || !user.password || !user.salt) {
      throw new Error("WRONG_PASSWORD");
    }
    if (!verifyPassword(currentPassword, user.salt, user.password)) {
      throw new Error("WRONG_PASSWORD");
    }
    const salt = randomSalt();
    updates.password = hashPassword(newPassword, salt);
    updates.salt = salt;
    updates.timePasswordChanged = dbWrite.fn.now();
    passwordChanged = true;
  }
  const nextEmail = body.email === undefined ? null : normalizeEmail(body.email);
  if (body.email !== undefined) {
    if (!nextEmail)
      throw new Error("INVALID_EMAIL");
    if (nextEmail !== user.email) {
      await ensureEmailUnique(c, nextEmail, user.id);
      const code = randomCode();
      await setCode(c, user.id, {
        codeField: "emailChangeCode",
        attemptsField: "emailChangeCodeAttempts",
        expiresField: "timeEmailChangeCodeExpired",
        code,
        expiresAt: getExpiresAt(CODE_EXPIRES_IN, 30 * 60),
        extra: {
          emailToChange: nextEmail
        }
      });
      await sendEmailChangeCode(c, nextEmail, user, code);
      emailChangeRequested = true;
    }
  }
  const nextPhone = body.phone === undefined ? null : normalizePhone(body.phone);
  if (body.phone !== undefined) {
    if (!nextPhone)
      throw new Error("INVALID_PHONE");
    if (nextPhone !== user.phone) {
      await ensurePhoneUnique(c, nextPhone, user.id);
      const code = randomCode();
      await setCode(c, user.id, {
        codeField: "phoneChangeCode",
        attemptsField: "phoneChangeCodeAttempts",
        expiresField: "timePhoneChangeCodeExpired",
        code,
        expiresAt: getExpiresAt(CODE_EXPIRES_IN, 30 * 60),
        extra: {
          phoneToChange: nextPhone
        }
      });
      await sendPhoneConfirmationCode(c, nextPhone, code);
      phoneChangeRequested = true;
    } else if (user.phone && !user.isPhoneVerified) {
      const code = randomCode();
      await setCode(c, user.id, {
        codeField: "phoneCode",
        attemptsField: "phoneCodeAttempts",
        expiresField: "timePhoneCodeExpired",
        code,
        expiresAt: getExpiresAt(CODE_EXPIRES_IN, 30 * 60)
      });
      await sendPhoneConfirmationCode(c, user.phone, code);
      phoneChangeRequested = true;
    }
  }
  if (Object.keys(updates).length) {
    await dbWrite("users").where({ id: authUser.id }).update({
      ...updates,
      timeUpdated: dbWrite.fn.now()
    });
  }
  c.set("result", {
    ok: true,
    passwordChanged,
    emailChangeRequested,
    phoneChangeRequested
  });
});
var confirmEmailChange = async (c) => {
  const { user, code } = await getConfirmationPayload(c, "email");
  if (!user.emailToChange)
    throw new Error("NOTHING_TO_CONFIRM");
  await verifyStoredCode(c, user, {
    code,
    codeField: "emailChangeCode",
    attemptsField: "emailChangeCodeAttempts",
    expiresField: "timeEmailChangeCodeExpired"
  });
  await ensureEmailUnique(c, user.emailToChange, user.id);
  const dbWrite = getDbWrite(c);
  await dbWrite("users").where({ id: user.id }).update({
    email: user.emailToChange,
    emailToChange: null,
    emailChangeCode: null,
    emailChangeCodeAttempts: 0,
    timeEmailChangeCodeExpired: null,
    isEmailVerified: true,
    role: getRoleAfterVerifiedIdentity(user.role),
    timeUpdated: dbWrite.fn.now()
  });
  await saveAuthResult(c, {
    ...user,
    role: getRoleAfterVerifiedIdentity(user.role),
    email: user.emailToChange,
    emailToChange: null,
    isEmailVerified: true
  });
};
login.post("/login/email", confirmEmailChange);
login.post("/login/email/confirm", confirmEmailChange);
login.post("/login/email/resend", async (c) => {
  const user = await getCurrentUserRecord(c);
  if (user.emailToChange) {
    const code2 = randomCode();
    await setCode(c, user.id, {
      codeField: "emailChangeCode",
      attemptsField: "emailChangeCodeAttempts",
      expiresField: "timeEmailChangeCodeExpired",
      code: code2,
      expiresAt: getExpiresAt(CODE_EXPIRES_IN, 30 * 60),
      extra: {
        emailToChange: user.emailToChange
      }
    });
    await sendEmailChangeCode(c, user.emailToChange, user, code2);
    c.set("result", { ok: true });
    return;
  }
  if (!user.email || user.isEmailVerified) {
    throw new Error("NOTHING_TO_CONFIRM");
  }
  const code = randomCode();
  await setCode(c, user.id, {
    codeField: "registerCode",
    attemptsField: "registerCodeAttempts",
    expiresField: "timeRegisterCodeExpired",
    code,
    expiresAt: getExpiresAt(CODE_EXPIRES_IN, 30 * 60)
  });
  await sendRegisterCode(c, user, code);
  c.set("result", { ok: true });
});
var confirmPhone = async (c) => {
  const { user, code } = await getConfirmationPayload(c, "phone");
  const dbWrite = getDbWrite(c);
  if (user.phoneToChange && user.phoneChangeCode) {
    await verifyStoredCode(c, user, {
      code,
      codeField: "phoneChangeCode",
      attemptsField: "phoneChangeCodeAttempts",
      expiresField: "timePhoneChangeCodeExpired"
    });
    await ensurePhoneUnique(c, user.phoneToChange, user.id);
    await dbWrite("users").where({ id: user.id }).update({
      phone: user.phoneToChange,
      phoneToChange: null,
      phoneChangeCode: null,
      phoneChangeCodeAttempts: 0,
      timePhoneChangeCodeExpired: null,
      isPhoneVerified: true,
      timeUpdated: dbWrite.fn.now()
    });
    await saveAuthResult(c, {
      ...user,
      phone: user.phoneToChange,
      phoneToChange: null,
      isPhoneVerified: true
    });
    return;
  }
  if (!user.phone || !user.phoneCode) {
    throw new Error("NOTHING_TO_CONFIRM");
  }
  await verifyStoredCode(c, user, {
    code,
    codeField: "phoneCode",
    attemptsField: "phoneCodeAttempts",
    expiresField: "timePhoneCodeExpired"
  });
  await clearCode(c, user.id, {
    codeField: "phoneCode",
    attemptsField: "phoneCodeAttempts",
    expiresField: "timePhoneCodeExpired",
    extra: {
      isPhoneVerified: true
    }
  });
  await saveAuthResult(c, {
    ...user,
    isPhoneVerified: true,
    phoneCode: null
  });
};
login.post("/login/phone", confirmPhone);
login.post("/login/phone/confirm", confirmPhone);
login.post("/login/phone/resend", async (c) => {
  const user = await getCurrentUserRecord(c);
  if (user.phoneToChange) {
    const code2 = randomCode();
    await setCode(c, user.id, {
      codeField: "phoneChangeCode",
      attemptsField: "phoneChangeCodeAttempts",
      expiresField: "timePhoneChangeCodeExpired",
      code: code2,
      expiresAt: getExpiresAt(CODE_EXPIRES_IN, 30 * 60),
      extra: {
        phoneToChange: user.phoneToChange
      }
    });
    await sendPhoneConfirmationCode(c, user.phoneToChange, code2);
    c.set("result", { ok: true });
    return;
  }
  if (!user.phone)
    throw new Error("NOTHING_TO_CONFIRM");
  const code = randomCode();
  await setCode(c, user.id, {
    codeField: "phoneCode",
    attemptsField: "phoneCodeAttempts",
    expiresField: "timePhoneCodeExpired",
    code,
    expiresAt: getExpiresAt(CODE_EXPIRES_IN, 30 * 60)
  });
  await sendPhoneConfirmationCode(c, user.phone, code);
  c.set("result", { ok: true });
});
login.get("/login/externals", async (c) => {
  const user = await getCurrentUserRecord(c);
  c.set("result", getOAuthServiceSummaries(user.oauthProviders));
});
login.get("/login/me", async (c) => {
  const user = await getCurrentUserRecord(c);
  const result = { ...toPublicAuthUser(user) };
  for (const field of USER_HIDDEN_FIELDS)
    delete result[field];
  c.set("result", {
    ...result,
    email: user.email || null,
    phone: user.phone || null,
    role: user.role || (isUserIdentityVerified(user) ? VERIFIED_ROLE2 : UNVERIFIED_ROLE2),
    roles: getUserRoles(user),
    permissionsHint: Object.keys(USER_VISIBLE_FOR),
    ownerPermissionsHint: USER_OWNER_PERMISSIONS
  });
});
for (const service of OAUTH_SERVICES)
  registerOAuthRoutes(service);
// src/modules/users.ts
import { Routings as Routings2 } from "the-api-routings";
var users = new Routings2;
var VERIFIED_ROLE3 = process.env.AUTH_VERIFIED_ROLE || process.env.AUTH_DEFAULT_ROLE || "registered";
var UNVERIFIED_ROLE3 = process.env.AUTH_UNVERIFIED_ROLE || "unverified";
var CODE_EXPIRES_IN2 = process.env.AUTH_CODE_EXPIRES_IN || "30m";
var USERS_ERRORS = {
  USER_NOT_FOUND: {
    code: 201,
    status: 404,
    description: "User not found"
  },
  EMAIL_EXISTS: {
    code: 202,
    status: 409,
    description: "Email already exists"
  },
  PHONE_EXISTS: {
    code: 203,
    status: 409,
    description: "Phone already exists"
  },
  LOGIN_EXISTS: {
    code: 204,
    status: 409,
    description: "Login already exists"
  },
  INVALID_EMAIL: {
    code: 205,
    status: 400,
    description: "Email is invalid"
  },
  INVALID_PHONE: {
    code: 206,
    status: 400,
    description: "Phone is invalid"
  },
  PASSWORD_REQUIRED: {
    code: 207,
    status: 400,
    description: "Password is required"
  },
  AVATAR_REQUIRED: {
    code: 208,
    status: 400,
    description: "Avatar file is required"
  }
};
var getRoleAfterEmailConfirmation = (role) => role === UNVERIFIED_ROLE3 || !role ? VERIFIED_ROLE3 : role;
var USERS_READ_ONLY_FIELDS = [
  "id",
  "timeCreated",
  "timeUpdated",
  "timeDeleted",
  "isDeleted",
  "password",
  "salt",
  "refresh",
  "timeRefreshExpired",
  "registerCode",
  "registerCodeAttempts",
  "timeRegisterCodeExpired",
  "recoverCode",
  "recoverCodeAttempts",
  "timeRecoverCodeExpired",
  "phoneCode",
  "phoneCodeAttempts",
  "timePhoneCodeExpired",
  "phoneChangeCode",
  "phoneChangeCodeAttempts",
  "timePhoneChangeCodeExpired",
  "phoneToChange",
  "emailChangeCode",
  "emailChangeCodeAttempts",
  "timeEmailChangeCodeExpired",
  "emailToChange",
  "oauthProviders",
  "avatar"
];
var CREATE_BASE_FIELDS = ["email", "password", "login", "phone", "fullName", "locale", "timezone"];
var UPDATE_BASE_FIELDS = ["fullName", "locale", "timezone"];
var trimString2 = (value) => {
  if (typeof value !== "string")
    return null;
  const result = value.trim();
  return result || null;
};
var getBodyObject2 = (c) => c.var.body && typeof c.var.body === "object" && !Array.isArray(c.var.body) ? c.var.body : {};
var usersCrudConfig = {
  table: "users",
  userIdFieldName: "id",
  permissions: {
    methods: ["GET", "POST", "PATCH", "DELETE"],
    owner: USER_OWNER_PERMISSIONS
  },
  validation: {
    body: {
      post: {
        email: { type: "string", required: true },
        password: { type: "string", required: true },
        login: { type: "string" },
        phone: { type: "string" },
        fullName: { type: "string" },
        locale: { type: "string" },
        timezone: { type: "string" }
      },
      patch: {
        email: { type: "string" },
        phone: { type: "string" },
        fullName: { type: "string" },
        locale: { type: "string" },
        timezone: { type: "string" },
        role: { type: "string" },
        isBlocked: { type: "boolean" },
        isDeleted: { type: "boolean" },
        isEmailInvalid: { type: "boolean" },
        isPhoneInvalid: { type: "boolean" },
        isEmailVerified: { type: "boolean" },
        isPhoneVerified: { type: "boolean" }
      }
    }
  },
  fieldRules: {
    hidden: USER_HIDDEN_FIELDS,
    readOnly: USERS_READ_ONLY_FIELDS,
    visibleFor: USER_VISIBLE_FOR,
    editableFor: USER_EDITABLE_FOR
  }
};
var sanitizeUserResult = (c, user) => sanitizeUser({
  c,
  user,
  hiddenFields: USER_HIDDEN_FIELDS,
  visibleFor: USER_VISIBLE_FOR,
  ownerPermissions: USER_OWNER_PERMISSIONS
});
var getUserById = async (c, id) => {
  const db = getDb(c);
  const user = await db("users").where({ id }).first();
  if (!user || user.isDeleted)
    throw new Error("USER_NOT_FOUND");
  return user;
};
var ensureEmailUnique2 = async (c, email, exceptId) => {
  const db = getDb(c);
  const query = db("users").whereRaw("LOWER(email) = ?", [email]);
  if (exceptId)
    query.whereNot({ id: exceptId });
  const existing = await query.first();
  if (existing)
    throw new Error("EMAIL_EXISTS");
};
var ensurePhoneUnique2 = async (c, phone, exceptId) => {
  const db = getDb(c);
  const query = db("users").where({ phone });
  if (exceptId)
    query.whereNot({ id: exceptId });
  const existing = await query.first();
  if (existing)
    throw new Error("PHONE_EXISTS");
};
var ensureLoginUnique2 = async (c, loginName, exceptId) => {
  const db = getDb(c);
  const query = db("users").whereRaw("LOWER(login) = ?", [loginName.toLowerCase()]);
  if (exceptId)
    query.whereNot({ id: exceptId });
  const existing = await query.first();
  if (existing)
    throw new Error("LOGIN_EXISTS");
};
var getEditableFields = (c, baseFields) => {
  const editable = new Set(baseFields);
  for (const [permission, fields] of Object.entries(USER_EDITABLE_FOR)) {
    if (hasPermission(c, permission)) {
      for (const field of fields)
        editable.add(field);
    }
  }
  return editable;
};
var assertRoutePermission = (c, permission) => {
  if (!hasPermission(c, permission))
    throw new Error("ACCESS_DENIED");
};
var sendEmailVerification = async (c, email, code) => {
  await sendEmail(c, {
    to: email,
    subject: "Confirm your email",
    text: `Use this code to confirm your email: ${code}`
  });
};
var sendPhoneVerification = async (c, phone, code) => {
  await sendSms(c, {
    to: phone,
    body: `Your confirmation code is ${code}`
  });
};
var parseUserId = (c) => {
  const rawId = c.req.param("id") || c.req.param().id || c.req.path.split("/").filter(Boolean).at(-1) || "";
  const id = Number(rawId);
  if (!Number.isInteger(id) || id < 1)
    throw new Error("USER_NOT_FOUND");
  return id;
};
users.errors(USERS_ERRORS);
users.post("/users", async (c) => {
  requireAuth(c);
  assertRoutePermission(c, "users.post");
  const body = getBodyObject2(c);
  const requestedFields = Object.keys(body);
  const editableFields = getEditableFields(c, CREATE_BASE_FIELDS);
  const deniedFields = requestedFields.filter((field) => !editableFields.has(field));
  if (deniedFields.length)
    throw new Error("ACCESS_DENIED");
  const email = normalizeEmail(body.email);
  const password = trimString2(body.password);
  const phone = body.phone === undefined || body.phone === null ? null : normalizePhone(body.phone);
  const loginName = trimString2(body.login);
  if (!email)
    throw new Error("INVALID_EMAIL");
  if (!password)
    throw new Error("PASSWORD_REQUIRED");
  if (body.phone !== undefined && body.phone !== null && !phone)
    throw new Error("INVALID_PHONE");
  await ensureEmailUnique2(c, email);
  if (phone)
    await ensurePhoneUnique2(c, phone);
  if (loginName)
    await ensureLoginUnique2(c, loginName);
  const dbWrite = getDbWrite(c);
  const salt = randomSalt();
  const passwordHash = hashPassword(password, salt);
  const emailVerificationCode = body.isEmailVerified === true ? null : randomCode();
  const phoneVerificationCode = phone && body.isPhoneVerified !== true ? randomCode() : null;
  const payload = {
    email,
    password: passwordHash,
    salt,
    fullName: trimString2(body.fullName),
    login: loginName,
    phone,
    locale: trimString2(body.locale),
    timezone: trimString2(body.timezone),
    role: trimString2(body.role) || (body.isEmailVerified === true ? VERIFIED_ROLE3 : UNVERIFIED_ROLE3),
    isBlocked: body.isBlocked === true,
    isDeleted: body.isDeleted === true,
    isEmailInvalid: body.isEmailInvalid === true,
    isPhoneInvalid: body.isPhoneInvalid === true,
    isEmailVerified: body.isEmailVerified === true,
    isPhoneVerified: body.isPhoneVerified === true || !phone,
    timePasswordChanged: dbWrite.fn.now(),
    refresh: randomToken(),
    timeRefreshExpired: new Date(0),
    registerCode: emailVerificationCode,
    registerCodeAttempts: 0,
    timeRegisterCodeExpired: emailVerificationCode ? getExpiresAt(CODE_EXPIRES_IN2, 30 * 60) : null,
    phoneCode: phoneVerificationCode,
    phoneCodeAttempts: 0,
    timePhoneCodeExpired: phoneVerificationCode ? getExpiresAt(CODE_EXPIRES_IN2, 30 * 60) : null
  };
  const [user] = await dbWrite("users").insert(payload).returning("*");
  if (emailVerificationCode)
    await sendEmailVerification(c, email, emailVerificationCode);
  if (phone && phoneVerificationCode)
    await sendPhoneVerification(c, phone, phoneVerificationCode);
  c.set("result", sanitizeUserResult(c, user));
});
users.patch("/users/:id", async (c) => {
  requireAuth(c);
  assertRoutePermission(c, "users.patch");
  const id = parseUserId(c);
  const body = getBodyObject2(c);
  const requestedFields = Object.keys(body);
  const editableFields = getEditableFields(c, UPDATE_BASE_FIELDS);
  const deniedFields = requestedFields.filter((field) => !editableFields.has(field));
  if (deniedFields.length)
    throw new Error("ACCESS_DENIED");
  const user = await getUserById(c, id);
  const dbWrite = getDbWrite(c);
  const updates = {};
  if (body.fullName !== undefined)
    updates.fullName = trimString2(body.fullName);
  if (body.locale !== undefined)
    updates.locale = trimString2(body.locale);
  if (body.timezone !== undefined)
    updates.timezone = trimString2(body.timezone);
  if (body.role !== undefined)
    updates.role = trimString2(body.role) || VERIFIED_ROLE3;
  if (body.isBlocked !== undefined)
    updates.isBlocked = body.isBlocked === true;
  if (body.isDeleted !== undefined)
    updates.isDeleted = body.isDeleted === true;
  if (body.isEmailInvalid !== undefined)
    updates.isEmailInvalid = body.isEmailInvalid === true;
  if (body.isPhoneInvalid !== undefined)
    updates.isPhoneInvalid = body.isPhoneInvalid === true;
  if (body.isEmailVerified !== undefined)
    updates.isEmailVerified = body.isEmailVerified === true;
  if (body.isEmailVerified === true && body.role === undefined) {
    updates.role = getRoleAfterEmailConfirmation(user.role);
  }
  if (body.isPhoneVerified !== undefined)
    updates.isPhoneVerified = body.isPhoneVerified === true;
  if (body.email !== undefined) {
    const email = normalizeEmail(body.email);
    if (!email)
      throw new Error("INVALID_EMAIL");
    if (email !== user.email) {
      await ensureEmailUnique2(c, email, user.id);
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
      updates.timeRegisterCodeExpired = code ? getExpiresAt(CODE_EXPIRES_IN2, 30 * 60) : null;
      if (code)
        await sendEmailVerification(c, email, code);
    }
  }
  if (body.phone !== undefined) {
    if (body.phone === null || body.phone === "") {
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
      if (!phone)
        throw new Error("INVALID_PHONE");
      if (phone !== user.phone) {
        await ensurePhoneUnique2(c, phone, user.id);
        const code = body.isPhoneVerified === true ? null : randomCode();
        updates.phone = phone;
        updates.phoneToChange = null;
        updates.phoneChangeCode = null;
        updates.phoneChangeCodeAttempts = 0;
        updates.timePhoneChangeCodeExpired = null;
        updates.isPhoneVerified = body.isPhoneVerified === true;
        updates.phoneCode = code;
        updates.phoneCodeAttempts = 0;
        updates.timePhoneCodeExpired = code ? getExpiresAt(CODE_EXPIRES_IN2, 30 * 60) : null;
        if (code)
          await sendPhoneVerification(c, phone, code);
      }
    }
  }
  if (body.isDeleted === true) {
    updates.timeDeleted = dbWrite.fn.now();
  } else if (body.isDeleted === false) {
    updates.timeDeleted = null;
  }
  if (Object.keys(updates).length) {
    await dbWrite("users").where({ id }).update({
      ...updates,
      timeUpdated: dbWrite.fn.now()
    });
  }
  const updated = await getUserById(c, id);
  c.set("result", sanitizeUserResult(c, updated));
});
users.delete("/users/:id", async (c) => {
  requireAuth(c);
  assertRoutePermission(c, "users.delete");
  const id = parseUserId(c);
  await getUserById(c, id);
  const dbWrite = getDbWrite(c);
  await dbWrite("users").where({ id }).update({
    isDeleted: true,
    timeDeleted: dbWrite.fn.now(),
    refresh: randomToken(),
    timeRefreshExpired: new Date(0),
    timeUpdated: dbWrite.fn.now()
  });
  c.set("result", { ok: true });
});
users.post("/users/:id/avatar", async (c) => {
  const authUser = requireAuth(c);
  const id = parseUserId(c);
  const isOwner = `${authUser.id}` === `${id}`;
  const canUpload = isOwner || hasPermission(c, "users.patch") || hasPermission(c, "users.uploadAvatar");
  if (!canUpload)
    throw new Error("ACCESS_DENIED");
  const user = await getUserById(c, id);
  const body = c.var.body && typeof c.var.body === "object" ? c.var.body : {};
  const avatar = body.avatar;
  if (!(avatar instanceof File))
    throw new Error("AVATAR_REQUIRED");
  const stored = await uploadFile(c, avatar, `users/${id}/avatar`);
  await deleteStoredFile(c, user.avatar || null);
  const dbWrite = getDbWrite(c);
  await dbWrite("users").where({ id }).update({
    avatar: stored.path,
    timeUpdated: dbWrite.fn.now()
  });
  const updated = await getUserById(c, id);
  c.set("result", sanitizeUserResult(c, updated));
});
users.delete("/users/:id/avatar", async (c) => {
  const authUser = requireAuth(c);
  const id = parseUserId(c);
  const isOwner = `${authUser.id}` === `${id}`;
  const canUpload = isOwner || hasPermission(c, "users.patch") || hasPermission(c, "users.uploadAvatar");
  if (!canUpload)
    throw new Error("ACCESS_DENIED");
  const user = await getUserById(c, id);
  await deleteStoredFile(c, user.avatar || null);
  const dbWrite = getDbWrite(c);
  await dbWrite("users").where({ id }).update({
    avatar: null,
    timeUpdated: dbWrite.fn.now()
  });
  const updated = await getUserById(c, id);
  c.set("result", sanitizeUserResult(c, updated));
});
users.crud(usersCrudConfig);

// src/index.ts
var moduleDir = dirname2(fileURLToPath(import.meta.url));
var migrationDir = resolve(moduleDir, "../migrations");
var migrationUpdateDir = resolve(moduleDir, "../migrationsUpdate");
export {
  users,
  migrationUpdateDir,
  migrationDir,
  login
};
