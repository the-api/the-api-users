# AGENTS.md

This file is an instruction manual for agents that build APIs for different
applications and connect `the-api-users` as the reusable users, login,
authentication, and authorization module.

## What the user must have first

The user must have:

- Node.js or Bun.
- `the-api` installed.
- `the-api-users` installed.
- PostgreSQL.
- Tables created for the examples in this document: the required `users` table
  and the example application tables `projects` and `tasks`.

Minimal install:

```bash
# npm
npm i the-api the-api-users the-api-roles

# or bun
bun add the-api the-api-users the-api-roles
```

PostgreSQL for local development:

```bash
createdb app_api
```

The required `users` table should normally be created through the module
migration:

```ts
import { TheAPI, middlewares } from 'the-api';
import Roles from 'the-api-roles';
import { login, users, migrationDir } from 'the-api-users';

const roles = new Roles({
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
});

const theAPI = new TheAPI({
  roles,
  migrationDirs: [migrationDir],
  routings: [
    middlewares.email,
    middlewares.files,
    users,
    login,
  ],
});

export default theAPI.up();
```

If you need to inspect the `users` table manually, it must match the module
migration:

```sql
create table if not exists users (
  id serial primary key,
  "timeCreated" timestamp not null default now(),
  "timeUpdated" timestamp,
  "timeDeleted" timestamp,
  "isBlocked" boolean not null default false,
  "isDeleted" boolean not null default false,
  login varchar(255) unique,
  password varchar(255),
  salt varchar(255),
  "timePasswordChanged" timestamp,
  email varchar(1024),
  "isEmailVerified" boolean not null default false,
  "isEmailInvalid" boolean not null default false,
  phone varchar(255) unique,
  "isPhoneVerified" boolean not null default false,
  "isPhoneInvalid" boolean not null default false,
  "fullName" varchar(1024),
  "displayName" varchar(255),
  avatar varchar(2048),
  role varchar(128),
  locale varchar(32),
  timezone varchar(32),
  refresh varchar(255),
  "timeRefreshExpired" timestamp,
  "oauthProviders" jsonb,
  "registerCode" varchar(128),
  "registerCodeAttempts" integer not null default 0,
  "timeRegisterCodeExpired" timestamp,
  "recoverCode" varchar(128),
  "recoverCodeAttempts" integer not null default 0,
  "timeRecoverCodeExpired" timestamp,
  "phoneCode" varchar(32),
  "phoneCodeAttempts" integer not null default 0,
  "timePhoneCodeExpired" timestamp,
  "phoneToChange" varchar(255),
  "phoneChangeCode" varchar(32),
  "phoneChangeCodeAttempts" integer not null default 0,
  "timePhoneChangeCodeExpired" timestamp,
  "emailToChange" varchar(1024),
  "emailChangeCode" varchar(128),
  "emailChangeCodeAttempts" integer not null default 0,
  "timeEmailChangeCodeExpired" timestamp
);
```

Example application tables used later in this document:

```sql
create table if not exists projects (
  id serial primary key,
  "ownerId" integer not null references users(id),
  title varchar(255) not null,
  status varchar(32) not null default 'active',
  "timeCreated" timestamp not null default now(),
  "timeUpdated" timestamp
);

create table if not exists tasks (
  id serial primary key,
  "projectId" integer not null references projects(id) on delete cascade,
  "assigneeId" integer references users(id),
  title varchar(255) not null,
  done boolean not null default false,
  "timeCreated" timestamp not null default now(),
  "timeUpdated" timestamp
);
```

## Module purpose

`the-api-users` adds ready-to-use routings to `the-api`:

- `login`: registration, e-mail confirmation, password login, refresh tokens,
  password recovery, profile edits, e-mail/phone changes, OAuth login, OAuth
  linking, and OAuth unlinking.
- `users`: users CRUD, route permissions, field permissions, owner visibility,
  and avatar upload.
- `migrationDir`: migration directory for creating the `users` table.
- `migrationUpdateDir`: idempotent migration directory that adds missing columns
  to an existing `users` table.

Use the module as the ready identity/auth layer. Do not reimplement `/login`,
refresh tokens, password hashing, or the users table in application code unless
the task explicitly asks you to change this package itself.

## Quick start API

Example `src/api.ts`:

```ts
import { TheAPI, middlewares } from 'the-api';
import Roles from 'the-api-roles';
import { login, users, migrationDir } from 'the-api-users';

const roles = new Roles({
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
});

const theAPI = new TheAPI({
  roles,
  migrationDirs: [migrationDir],
  routings: [
    middlewares.logs,
    middlewares.errors,
    middlewares.email,
    middlewares.files,
    users,
    login,
  ],
});

await theAPI.up();
```

Minimal `.env`:

```env
JWT_SECRET=change-me
JWT_EXPIRES_IN=1h

AUTH_DEFAULT_ROLE=registered
AUTH_VERIFIED_ROLE=registered
AUTH_UNVERIFIED_ROLE=unverified
AUTH_REQUIRE_EMAIL_VERIFICATION=true
AUTH_CODE_EXPIRES_IN=30m
AUTH_RECOVER_CODE_LENGTH=36
AUTH_RECOVER_CODE_EXPIRES_IN=30m
AUTH_REFRESH_EXPIRES_IN=30d
AUTH_MAX_CODE_ATTEMPTS=5
AUTH_PASSWORD_HASH_ALGORITHM=scrypt
AUTH_SCRYPT_N=16384
AUTH_SCRYPT_R=8
AUTH_SCRYPT_P=1
AUTH_SCRYPT_MAXMEM=33554432

DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=postgres
DB_DATABASE=app_api

DB_WRITE_HOST=localhost
DB_WRITE_PORT=5432
DB_WRITE_USER=postgres
DB_WRITE_PASSWORD=postgres
DB_WRITE_DATABASE=app_api

FILES_FOLDER=public/files
```

## Response envelope

Every endpoint returns the standard `the-api` envelope:

```json
{
  "result": {},
  "meta": {},
  "relations": {},
  "error": false,
  "requestTime": 6,
  "serverTime": "2026-03-14T12:00:00.000Z"
}
```

A successful auth response usually looks like this:

```json
{
  "result": {
    "id": 1,
    "email": "john@example.com",
    "phone": null,
    "fullName": "John Doe",
    "role": "registered",
    "roles": ["registered"],
    "avatar": null,
    "locale": "en",
    "timezone": "UTC",
    "isEmailVerified": true,
    "isPhoneVerified": false,
    "oauthServices": [],
    "token": "jwt...",
    "refresh": "refresh-token..."
  },
  "error": false
}
```

Errors also come back in `result`; branch on `result.name`:

```json
{
  "result": {
    "name": "EMAIL_NOT_CONFIRMED",
    "message": "EMAIL_NOT_CONFIRMED"
  },
  "error": true
}
```

## Main auth endpoints

- `POST /login/register`: create a user.
- `POST /login/register/confirm`: confirm registration e-mail.
- `POST /login/register/check`: alias for registration confirmation.
- `POST /login/register/resend`: send a fresh registration confirmation code.
- `POST /login`: password login by `email` or `login`.
- `POST /login/refresh`: refresh JWT by refresh token.
- `GET /login/refresh?refresh=...`: refresh through query string.
- `POST /login/forgot`: request a recovery code.
- `POST /login/restore`: set a new password by recovery code.
- `PATCH /login`: edit own profile, password, e-mail, or phone.
- `POST /login/email`: confirm e-mail change.
- `POST /login/email/confirm`: alias for confirming e-mail change.
- `POST /login/email/resend`: send a fresh e-mail code.
- `POST /login/phone`: confirm phone or phone change.
- `POST /login/phone/confirm`: alias for confirming phone.
- `POST /login/phone/resend`: send a fresh phone code.
- `GET /login/me`: get the current user.
- `GET /login/externals`: list linked OAuth providers.

OAuth endpoints for each service `apple`, `facebook`, `github`, `google`,
`linkedin`, `microsoft`, and `twitter`:

- `GET /login/{service}`: redirect to the OAuth provider.
- `POST /login/{service}`: accept `code`, `accessToken`, or `idToken`.
- `DELETE /login/{service}`: unlink the provider.

## Users endpoints

- `GET /users`
- `GET /users/:id`
- `POST /users`
- `PATCH /users/:id`
- `DELETE /users/:id`
- `POST /users/:id/avatar`
- `DELETE /users/:id/avatar`

Do not insert users directly into the database from application business code.
For user self-registration, use `/login/register`. For admin creation, use
`POST /users`, because the module normalizes e-mail/phone, hashes the password,
and generates salt, refresh, and verification codes.

## Roles and permissions

Route-level permissions:

- `users.get`
- `users.post`
- `users.patch`
- `users.delete`

Field visibility permissions:

- `users.viewEmail`: see `email`, `isEmailVerified`.
- `users.viewPhone`: see `phone`, `isPhoneVerified`.
- `users.viewRole`: see `role`.
- `users.viewLocale`: see `locale`, `timezone`.
- `users.viewStatus`: see `isBlocked`, `isDeleted`, `isEmailInvalid`,
  `isPhoneInvalid`.
- `users.viewMeta`: see `timeCreated`, `timeUpdated`, `timeDeleted`.

Field edit permissions:

- `users.editProfile`: edit `fullName`, `locale`, `timezone`.
- `users.editEmail`: edit `email`.
- `users.editPhone`: edit `phone`.
- `users.editRole`: edit `role`.
- `users.editStatus`: edit block/delete/invalid flags.
- `users.editVerification`: edit verification flags.
- `users.uploadAvatar`: upload avatar.

Fields that are hidden unless explicitly exposed by the module rules:
`password`, `salt`, `refresh`, refresh/code expiration fields, verification
codes, pending e-mail/phone fields, `oauthProviders`, `email`, and `phone`.

The owner of `/users/:id` receives these owner visibility permissions on their
own record: `users.viewEmail`, `users.viewPhone`, `users.viewRole`,
`users.viewLocale`, and `users.viewMeta`.

## Important auth behavior

- If `AUTH_REQUIRE_EMAIL_VERIFICATION=true`, registration creates an
  `unverified` user, returns `refresh`, and does not issue a normal JWT until
  e-mail is confirmed.
- If `AUTH_REQUIRE_EMAIL_VERIFICATION` is not `true`, registration immediately
  returns `token` and `refresh`.
- JWT payload contains `userId`, `role`, `roles`, `email`, `phone`, and
  `fullName`.
- Passwords are hashed with `scrypt` by default.
- `AUTH_PASSWORD_HASH_ALGORITHM=sha256` is supported for legacy projects.
- `POST /login/refresh` keeps the same refresh token and extends its expiry.
- Password/OAuth login reuses the current refresh token until it expires.
- Password restore and user deletion invalidate old refresh tokens.
- `POST /login/forgot` always returns `{ "ok": true }`, even when the e-mail is
  unknown.
- E-mail normalization is trim + lowercase.
- Phone normalization removes extra characters and preserves the leading `+`.
- `AUTH_MAX_CODE_ATTEMPTS` controls the maximum number of code attempts.

## OAuth

Supported providers:

- Apple
- Facebook
- Google
- GitHub
- LinkedIn
- Microsoft
- Twitter/X

Behavior:

- If the provider account is already linked, the user receives normal `token`
  and `refresh`.
- If the provider returns an e-mail or phone that belongs to an existing user,
  that user is logged in and the provider is linked automatically.
- If no user exists, a new user is created without a local password:
  `password = ""`, with a generated `salt`.
- A new OAuth user receives a `login` built from the e-mail local part or phone
  plus a random number.
- OAuth identity with e-mail/phone is treated as verified.
- If the role was `unverified`, it is promoted to `registered`.
- If `Authorization: Bearer <token>` is sent to `POST /login/{service}`, the
  provider is linked to the current user.
- `DELETE /login/{service}` removes the provider from `users.oauthProviders`.
- The last available login method cannot be unlinked if the user has no local
  password.
- Provider access tokens are not stored in `users`.

OAuth environment variables:

```env
AUTH_GOOGLE_CLIENT_ID=
AUTH_GOOGLE_CLIENT_SECRET=
AUTH_GOOGLE_REDIRECT_URI=
AUTH_GOOGLE_SCOPE=openid email profile
AUTH_GOOGLE_ACCESS_TYPE=offline
AUTH_GOOGLE_PROMPT=consent

AUTH_GITHUB_CLIENT_ID=
AUTH_GITHUB_CLIENT_SECRET=
AUTH_GITHUB_REDIRECT_URI=
AUTH_GITHUB_SCOPE=read:user user:email

AUTH_FACEBOOK_CLIENT_ID=
AUTH_FACEBOOK_CLIENT_SECRET=
AUTH_FACEBOOK_REDIRECT_URI=
AUTH_FACEBOOK_SCOPE=email public_profile
AUTH_FACEBOOK_FIELDS=id,email,first_name,last_name,name,picture

AUTH_LINKEDIN_CLIENT_ID=
AUTH_LINKEDIN_CLIENT_SECRET=
AUTH_LINKEDIN_REDIRECT_URI=
AUTH_LINKEDIN_SCOPE=openid profile email

AUTH_MICROSOFT_CLIENT_ID=
AUTH_MICROSOFT_CLIENT_SECRET=
AUTH_MICROSOFT_REDIRECT_URI=
AUTH_MICROSOFT_SCOPE=openid profile email offline_access User.Read
AUTH_MICROSOFT_TENANT_ID=common

AUTH_TWITTER_CLIENT_ID=
AUTH_TWITTER_CLIENT_SECRET=
AUTH_TWITTER_REDIRECT_URI=
AUTH_TWITTER_SCOPE=tweet.read users.read offline.access
AUTH_TWITTER_FIELDS=id,name,username,profile_image_url

AUTH_APPLE_CLIENT_ID=
AUTH_APPLE_CLIENT_SECRET=
AUTH_APPLE_TEAM_ID=
AUTH_APPLE_KEY_ID=
AUTH_APPLE_PRIVATE_KEY=
AUTH_APPLE_REDIRECT_URI=
AUTH_APPLE_SCOPE=name email
```

A provider is unavailable when required `AUTH_*` variables are missing. In that
case `GET /login/{service}` and `POST /login/{service}` respond like an
unsupported provider.

## Common errors

Auth errors:

- `USER_NOT_FOUND`: user was not found, is deleted, refresh is invalid, or
  password login failed.
- `USER_ACCESS_DENIED`: user is blocked.
- `EMAIL_EXISTS`
- `PHONE_EXISTS`
- `LOGIN_EXISTS`
- `EMAIL_NOT_CONFIRMED`
- `INVALID_OR_EXPIRED_CODE`
- `WRONG_CODE`
- `WRONG_PASSWORD`
- `NO_TOKEN`
- `INVALID_EMAIL`
- `INVALID_PHONE`
- `PASSWORD_REQUIRED`
- `LOGIN_OR_EMAIL_REQUIRED`
- `NOTHING_TO_CONFIRM`
- `EMAIL_ALREADY_CONFIRMED`
- `SMS_SEND_FAILED`
- `OAUTH_SERVICE_NOT_SUPPORTED`
- `OAUTH_CONFIG_NOT_FOUND`
- `OAUTH_TOKEN_REQUIRED`
- `OAUTH_INVALID_TOKEN`
- `OAUTH_INVALID_STATE`
- `OAUTH_CONFLICT`
- `OAUTH_IDENTITY_REQUIRED`
- `OAUTH_INVALID_REDIRECT_URI`
- `OAUTH_LAST_LOGIN_METHOD`

Users errors:

- `USER_NOT_FOUND`
- `EMAIL_EXISTS`
- `PHONE_EXISTS`
- `LOGIN_EXISTS`
- `INVALID_EMAIL`
- `INVALID_PHONE`
- `PASSWORD_REQUIRED`
- `AVATAR_REQUIRED`
- `ACCESS_DENIED`
- `NOT_FOUND`

## How to build application APIs on top of this module

For application domain entities, use `users.id` as the owner, author, account,
or assignee foreign key. In this document, `projects.ownerId` and
`tasks.assigneeId` are examples.

Typical approach:

- Keep all public auth flows in `login`.
- Keep admin/user management in `users`.
- In custom routings, read `c.var.user.userId` and roles from the JWT.
- For owner-only resources, compare `resource.ownerId` with
  `c.var.user.userId`.
- For admin-only actions, add permissions to `the-api-roles`.
- Do not store JWTs in application tables.
- Do not store provider access tokens unless a separate OAuth integration
  explicitly requires it.

Example domain request:

```http
GET /projects
Authorization: Bearer jwt...
```

Expected behavior:

- `registered` sees their own projects.
- `admin` sees all projects.
- `guest` receives `ACCESS_DENIED`.

## FAQ with request and response examples

### Q: How do I register a user?

Request:

```bash
curl -X POST "$API/login/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "secret-123",
    "fullName": "John Doe",
    "locale": "en",
    "timezone": "UTC"
  }'
```

Response when `AUTH_REQUIRE_EMAIL_VERIFICATION=true`:

```json
{
  "result": {
    "id": 1,
    "email": "john@example.com",
    "phone": null,
    "fullName": "John Doe",
    "role": "unverified",
    "roles": ["unverified"],
    "avatar": null,
    "locale": "en",
    "timezone": "UTC",
    "isEmailVerified": false,
    "isPhoneVerified": false,
    "oauthServices": [],
    "ok": true,
    "refresh": "refresh-token...",
    "emailConfirmationRequired": true,
    "phoneConfirmationRequired": false
  },
  "error": false
}
```

### Q: How do I confirm e-mail after registration?

Request:

```bash
curl -X POST "$API/login/register/confirm" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "code": "123456"
  }'
```

Response:

```json
{
  "result": {
    "id": 1,
    "email": "john@example.com",
    "role": "registered",
    "roles": ["registered"],
    "isEmailVerified": true,
    "token": "jwt...",
    "refresh": "refresh-token..."
  },
  "error": false
}
```

### Q: What happens if the user logs in before confirming e-mail?

Request:

```bash
curl -X POST "$API/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "secret-123"
  }'
```

Response:

```json
{
  "result": {
    "name": "EMAIL_NOT_CONFIRMED",
    "message": "EMAIL_NOT_CONFIRMED"
  },
  "error": true
}
```

### Q: How do I resend the registration confirmation code?

Request:

```bash
curl -X POST "$API/login/register/resend" \
  -H "Content-Type: application/json" \
  -d '{"email":"john@example.com"}'
```

Response:

```json
{
  "result": {
    "ok": true
  },
  "error": false
}
```

### Q: How do I log in with e-mail and password?

Request:

```bash
curl -X POST "$API/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "secret-123"
  }'
```

Response:

```json
{
  "result": {
    "id": 1,
    "email": "john@example.com",
    "role": "registered",
    "roles": ["registered"],
    "token": "jwt...",
    "refresh": "refresh-token..."
  },
  "error": false
}
```

### Q: Can I log in with `login` instead of e-mail?

Yes, if the user has a `login` value.

Request:

```bash
curl -X POST "$API/login" \
  -H "Content-Type: application/json" \
  -d '{
    "login": "john",
    "password": "secret-123"
  }'
```

Response:

```json
{
  "result": {
    "id": 1,
    "email": "john@example.com",
    "role": "registered",
    "roles": ["registered"],
    "token": "jwt...",
    "refresh": "refresh-token..."
  },
  "error": false
}
```

### Q: How do I refresh JWT by refresh token?

Request:

```bash
curl -X POST "$API/login/refresh" \
  -H "Content-Type: application/json" \
  -d '{"refresh":"refresh-token..."}'
```

Response:

```json
{
  "result": {
    "id": 1,
    "email": "john@example.com",
    "token": "new-jwt...",
    "refresh": "refresh-token..."
  },
  "error": false
}
```

### Q: How do I get the current user?

Request:

```bash
curl "$API/login/me" \
  -H "Authorization: Bearer $TOKEN"
```

Response:

```json
{
  "result": {
    "id": 1,
    "email": "john@example.com",
    "phone": null,
    "fullName": "John Doe",
    "role": "registered",
    "roles": ["registered"],
    "isEmailVerified": true
  },
  "error": false
}
```

### Q: How do I update my own profile?

Request:

```bash
curl -X PATCH "$API/login" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "fullName": "John Updated",
    "locale": "uk",
    "timezone": "Europe/Kyiv"
  }'
```

Response:

```json
{
  "result": {
    "ok": true,
    "passwordChanged": false,
    "emailChangeRequested": false,
    "phoneChangeRequested": false
  },
  "error": false
}
```

### Q: How do I change password?

Request:

```bash
curl -X PATCH "$API/login" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "password": "secret-123",
    "newPassword": "new-secret-456"
  }'
```

Response:

```json
{
  "result": {
    "ok": true,
    "passwordChanged": true,
    "emailChangeRequested": false,
    "phoneChangeRequested": false
  },
  "error": false
}
```

### Q: How do I request an e-mail change?

Request:

```bash
curl -X PATCH "$API/login" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"john.new@example.com"}'
```

Response:

```json
{
  "result": {
    "ok": true,
    "passwordChanged": false,
    "emailChangeRequested": true,
    "phoneChangeRequested": false
  },
  "error": false
}
```

### Q: How do I confirm an e-mail change?

Request:

```bash
curl -X POST "$API/login/email" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"code":"123456"}'
```

Response:

```json
{
  "result": {
    "id": 1,
    "email": "john.new@example.com",
    "isEmailVerified": true,
    "token": "new-jwt...",
    "refresh": "refresh-token..."
  },
  "error": false
}
```

### Q: How do I request and confirm phone?

Request:

```bash
curl -X PATCH "$API/login" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"phone":"+15550000001"}'
```

Response:

```json
{
  "result": {
    "ok": true,
    "passwordChanged": false,
    "emailChangeRequested": false,
    "phoneChangeRequested": true
  },
  "error": false
}
```

Confirm request:

```bash
curl -X POST "$API/login/phone" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"code":"123456"}'
```

Confirm response:

```json
{
  "result": {
    "id": 1,
    "phone": "+15550000001",
    "isPhoneVerified": true,
    "token": "new-jwt...",
    "refresh": "refresh-token..."
  },
  "error": false
}
```

### Q: How do I recover password?

Request recovery code:

```bash
curl -X POST "$API/login/forgot" \
  -H "Content-Type: application/json" \
  -d '{"email":"john@example.com"}'
```

Response:

```json
{
  "result": {
    "ok": true
  },
  "error": false
}
```

Set new password:

```bash
curl -X POST "$API/login/restore" \
  -H "Content-Type: application/json" \
  -d '{
    "code": "recovery-code",
    "password": "new-secret-456"
  }'
```

Response:

```json
{
  "result": {
    "ok": true
  },
  "error": false
}
```

### Q: How does an admin create a user?

Request:

```bash
curl -X POST "$API/users" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user-1@example.com",
    "password": "pass-1",
    "fullName": "User One",
    "locale": "uk",
    "timezone": "Europe/Kyiv"
  }'
```

Response:

```json
{
  "result": {
    "id": 2,
    "email": "user-1@example.com",
    "fullName": "User One",
    "role": "unverified",
    "locale": "uk",
    "timezone": "Europe/Kyiv",
    "isEmailVerified": false
  },
  "error": false
}
```

### Q: Why do `password`, `salt`, and `refresh` not appear in `/users`?

Because they are hidden fields. The module intentionally never returns secret
fields to owners or admins.

Request:

```bash
curl "$API/users?_sort=id" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

Response:

```json
{
  "result": [
    {
      "id": 1,
      "email": "john@example.com",
      "fullName": "John Doe",
      "role": "registered"
    }
  ],
  "meta": {
    "total": 1
  },
  "error": false
}
```

### Q: How does an admin update a user?

Request:

```bash
curl -X PATCH "$API/users/2" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user-1-updated@example.com",
    "fullName": "Updated User",
    "isEmailVerified": false
  }'
```

Response:

```json
{
  "result": {
    "id": 2,
    "email": "user-1-updated@example.com",
    "fullName": "Updated User",
    "isEmailVerified": false
  },
  "error": false
}
```

### Q: How does an admin delete a user?

Request:

```bash
curl -X DELETE "$API/users/2" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

Response:

```json
{
  "result": {
    "ok": true
  },
  "error": false
}
```

Deletion is soft-delete: the module sets `isDeleted=true`,
`timeDeleted=now()`, and invalidates the refresh token.

### Q: How do I upload an avatar?

Request:

```bash
curl -X POST "$API/users/1/avatar" \
  -H "Authorization: Bearer $TOKEN" \
  -F "avatar=@avatar.png"
```

Response:

```json
{
  "result": {
    "id": 1,
    "avatar": "users/1/avatar/file-name.png"
  },
  "error": false
}
```

This requires `middlewares.files` and `FILES_FOLDER`, or file middleware storage.

### Q: How do I start OAuth login with Google?

Browser redirect:

```bash
curl -i "$API/login/google"
```

Response:

```http
HTTP/1.1 302 Found
Location: https://accounts.google.com/o/oauth2/v2/auth?...
```

After provider callback, the frontend sends `code` and `state`:

```bash
curl -X POST "$API/login/google" \
  -H "Content-Type: application/json" \
  -d '{
    "code": "provider-auth-code",
    "state": "provider-state"
  }'
```

Response:

```json
{
  "result": {
    "id": 1,
    "email": "john@example.com",
    "oauthServices": ["google"],
    "token": "jwt...",
    "refresh": "refresh-token..."
  },
  "error": false
}
```

### Q: How do I use OAuth login when the client already has a provider access token?

Request:

```bash
curl -X POST "$API/login/github" \
  -H "Content-Type: application/json" \
  -d '{"accessToken":"github-access-token"}'
```

Response:

```json
{
  "result": {
    "id": 1,
    "email": "john@example.com",
    "oauthServices": ["github"],
    "token": "jwt...",
    "refresh": "refresh-token..."
  },
  "error": false
}
```

### Q: How do I link an OAuth provider to an already logged-in user?

Request:

```bash
curl -X POST "$API/login/github" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"accessToken":"github-access-token"}'
```

Response:

```json
{
  "result": {
    "id": 1,
    "oauthServices": ["github"],
    "token": "new-jwt...",
    "refresh": "refresh-token..."
  },
  "error": false
}
```

### Q: How do I list linked OAuth providers?

Request:

```bash
curl "$API/login/externals" \
  -H "Authorization: Bearer $TOKEN"
```

Response:

```json
{
  "result": [
    {
      "service": "google",
      "email": "john@example.com",
      "phone": null,
      "fullName": "John Doe",
      "avatar": "https://cdn.example.com/avatar.png",
      "linkedAt": "2026-03-14T12:00:00.000Z",
      "updatedAt": "2026-03-14T12:00:00.000Z"
    }
  ],
  "error": false
}
```

### Q: How do I unlink an OAuth provider?

Request:

```bash
curl -X DELETE "$API/login/github" \
  -H "Authorization: Bearer $TOKEN"
```

Response:

```json
{
  "result": {
    "ok": true,
    "oauthServices": ["google"]
  },
  "error": false
}
```

If this is the last available login method and the user has no local password,
the module returns `OAUTH_LAST_LOGIN_METHOD`.

### Q: What does a missing token error look like?

Request:

```bash
curl "$API/login/me"
```

Response:

```json
{
  "result": {
    "name": "NO_TOKEN",
    "message": "NO_TOKEN"
  },
  "error": true
}
```

### Q: What does a permission error look like?

Request:

```bash
curl -X POST "$API/users" \
  -H "Authorization: Bearer $REGISTERED_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"x@example.com","password":"pass"}'
```

Response:

```json
{
  "result": {
    "name": "ACCESS_DENIED",
    "message": "ACCESS_DENIED"
  },
  "error": true
}
```

### Q: How do I use `users.id` in application tables?

Create domain records with foreign keys to `users.id`.

Request:

```bash
curl -X POST "$API/projects" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title":"First project"}'
```

Expected domain response:

```json
{
  "result": {
    "id": 1,
    "ownerId": 1,
    "title": "First project",
    "status": "active"
  },
  "error": false
}
```

In the implementation, `ownerId` should come from the JWT user id, not from the
request body:

```ts
const userId = c.var.user.userId;
```

### Q: Which variables are needed for e-mail, SMS, and file flows?

E-mail code delivery uses `middlewares.email` when it is mounted. SMS uses
Twilio when these variables are set:

```env
SMS_PROVIDER=twilio
TWILIO_ACCOUNT_SID=
TWILIO_AUTH_TOKEN=
TWILIO_FROM=
```

Avatar upload uses `c.var.files.upload` when the file middleware provides
storage. Otherwise set:

```env
FILES_FOLDER=public/files
```

### Q: Should I mount `migrationUpdateDir`?

For a new project, `migrationDir` is enough. If the application already has a
`users` table and needs missing auth/OAuth columns added without recreating the
table, add `migrationUpdateDir`.

```ts
import { migrationDir, migrationUpdateDir } from 'the-api-users';

const theAPI = new TheAPI({
  migrationDirs: [migrationDir, migrationUpdateDir],
});
```

### Q: What happens when an OAuth provider is not configured?

`GET /login/{service}` and `POST /login/{service}` return
`OAUTH_SERVICE_NOT_SUPPORTED`.

Response:

```json
{
  "result": {
    "name": "OAUTH_SERVICE_NOT_SUPPORTED",
    "message": "OAUTH_SERVICE_NOT_SUPPORTED"
  },
  "error": true
}
```

Check `AUTH_{SERVICE}_CLIENT_ID`, `AUTH_{SERVICE}_CLIENT_SECRET`, and
`AUTH_{SERVICE}_REDIRECT_URI`.

### Q: Which commands should be used while developing this package?

```bash
bun run test
bun run build
```

Tests use Bun test and cover login, users, OAuth, and password hashing.

## Final checklist for agents

- `the-api-users` is mounted instead of copying auth logic.
- `migrationDir` is added to `migrationDirs`; for an existing `users` table,
  `migrationUpdateDir` was considered.
- PostgreSQL environment variables are configured for read/write connections.
- `JWT_SECRET` is non-empty in production.
- Roles include the required `users.*` permissions.
- `middlewares.email` is mounted when e-mail codes are needed.
- `middlewares.files` and storage are mounted when avatar upload is needed.
- OAuth env is set only for providers that are actually enabled.
- Application domain tables reference `users.id`.
- The body does not accept `ownerId` when owner must be the current user.
- Errors are handled by `result.name`.
