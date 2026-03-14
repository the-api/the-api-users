# the-api-users

- [the-api-users](#the-api-users)
  - [Installation](#installation)
  - [Quick Start](#quick-start)
  - [Env](#env)
  - [Response Format](#response-format)
  - [Permissions](#permissions)
  - [Endpoints](#endpoints)
    - [Auth](#auth)
      - [`POST /login/register`](#post-loginregister)
      - [`POST /login/register/confirm`](#post-loginregisterconfirm)
      - [`POST /login/register/check`](#post-loginregistercheck)
      - [`POST /login/register/resend`](#post-loginregisterresend)
      - [`POST /login`](#post-login)
      - [`POST /login/refresh`](#post-loginrefresh)
      - [`GET /login/refresh`](#get-loginrefresh)
      - [`POST /login/forgot`](#post-loginforgot)
      - [`POST /login/restore`](#post-loginrestore)
      - [`PATCH /login`](#patch-login)
      - [`POST /login/email`](#post-loginemail)
      - [`POST /login/email/confirm`](#post-loginemailconfirm)
      - [`POST /login/email/resend`](#post-loginemailresend)
      - [`POST /login/phone`](#post-loginphone)
      - [`POST /login/phone/confirm`](#post-loginphoneconfirm)
      - [`POST /login/phone/resend`](#post-loginphoneresend)
      - [`GET /login/me`](#get-loginme)
    - [Users CRUD](#users-crud)
      - [`GET /users`](#get-users)
      - [`GET /users/:id`](#get-usersid)
      - [`POST /users`](#post-users)
      - [`PATCH /users/:id`](#patch-usersid)
      - [`DELETE /users/:id`](#delete-usersid)
      - [`POST /users/:id/avatar`](#post-usersidavatar)
      - [`DELETE /users/:id/avatar`](#delete-usersidavatar)
  - [Development](#development)

Users/auth module for `the-api`.

It provides:

- registration with e-mail confirmation
- login with access token + refresh token
- refresh flow
- password recovery
- e-mail change with confirmation
- phone confirmation and phone change with confirmation
- users CRUD with field-level visibility/edit permissions
- avatar upload

## Installation

```bash
npm i the-api-users
```

## Quick Start

```ts
import { TheAPI, middlewares } from 'the-api';
import { roles } from 'the-api-roles';
import { login, users } from 'the-api-users';

roles.init({
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
  routings: [
    middlewares.email,
    middlewares.files,
    users,
    login,
  ],
});

export default theAPI.up();
```

Notes:

- Use `middlewares.email` if you want actual e-mail delivery.
- Use `middlewares.files` if you want file storage handled by `the-api`.
- Phone codes are sent through Twilio when `SMS_PROVIDER=twilio` and `TWILIO_*` env vars are configured.
- If email/SMS delivery is not configured, codes are still generated and logged.
- Migrations are attached to `users`. If you use `login` without `users`, pass `migrationDirs: ['./src/migrations']` manually.

## Env

See [.env.example](./.env.example).

Important vars:

- `JWT_SECRET`
- `JWT_EXPIRES_IN`
- `AUTH_DEFAULT_ROLE`
- `AUTH_VERIFIED_ROLE`
- `AUTH_UNVERIFIED_ROLE`
- `AUTH_REQUIRE_EMAIL_VERIFICATION`
- `AUTH_CODE_EXPIRES_IN`
- `AUTH_RECOVER_CODE_EXPIRES_IN`
- `AUTH_REFRESH_EXPIRES_IN`
- `AUTH_MAX_CODE_ATTEMPTS`
- `EMAIL_*`
- `FILES_FOLDER` or `MINIO_*`
- `SMS_PROVIDER`, `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM`

## Response Format

All endpoints return the standard `the-api` envelope:

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

Examples below show only representative `result` payloads plus the envelope around them.

## Permissions

Route-level permissions:

- `users.get`
- `users.post`
- `users.patch`
- `users.delete`

Field visibility permissions:

- `users.viewEmail`
- `users.viewPhone`
- `users.viewRole`
- `users.viewLocale`
- `users.viewStatus`
- `users.viewMeta`

Field edit permissions:

- `users.editProfile`
- `users.editEmail`
- `users.editPhone`
- `users.editRole`
- `users.editStatus`
- `users.editVerification`
- `users.uploadAvatar`

## Endpoints

Base URL in examples:

```bash
export API=http://localhost:7788
export TOKEN=your_access_token
export REFRESH=your_refresh_token
```

### Auth

#### `POST /login/register`

Create a user with role `unverified` and send e-mail/phone confirmation codes if needed.

```bash
curl -X POST "$API/login/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "secret-123",
    "fullName": "John Doe",
    "phone": "+15550000001",
    "locale": "en",
    "timezone": "UTC"
  }'
```

```json
{
  "result": {
    "id": 1,
    "email": "john@example.com",
    "phone": "+15550000001",
    "fullName": "John Doe",
    "role": "unverified",
    "roles": ["unverified"],
    "avatar": null,
    "locale": "en",
    "timezone": "UTC",
    "isEmailVerified": false,
    "isPhoneVerified": false,
    "ok": true,
    "emailConfirmationRequired": true,
    "phoneConfirmationRequired": true
  },
  "error": false
}
```

#### `POST /login/register/confirm`

Confirm registration by e-mail code and receive access/refresh tokens.

```bash
curl -X POST "$API/login/register/confirm" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "code": "123456"
  }'
```

```json
{
  "result": {
    "id": 1,
    "email": "john@example.com",
    "phone": "+15550000001",
    "fullName": "John Doe",
    "role": "unverified",
    "roles": ["registered"],
    "avatar": null,
    "locale": "en",
    "timezone": "UTC",
    "isEmailVerified": true,
    "isPhoneVerified": false,
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh": "Wm9Qd3J0Q..."
  },
  "error": false
}
```

#### `POST /login/register/check`

Alias of `POST /login/register/confirm`.

```bash
curl -X POST "$API/login/register/check" \
  -H "Content-Type: application/json" \
  -d '{"email":"john@example.com","code":"123456"}'
```

Response is the same as `POST /login/register/confirm`.

#### `POST /login/register/resend`

Resend registration e-mail confirmation code.

```bash
curl -X POST "$API/login/register/resend" \
  -H "Content-Type: application/json" \
  -d '{"email":"john@example.com"}'
```

```json
{
  "result": {
    "ok": true
  },
  "error": false
}
```

#### `POST /login`

Login by e-mail or login + password.

```bash
curl -X POST "$API/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "secret-123"
  }'
```

```json
{
  "result": {
    "id": 1,
    "email": "john@example.com",
    "phone": "+15550000001",
    "fullName": "John Doe",
    "role": "registered",
    "roles": ["registered"],
    "avatar": null,
    "locale": "en",
    "timezone": "UTC",
    "isEmailVerified": true,
    "isPhoneVerified": false,
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh": "Wm9Qd3J0Q..."
  },
  "error": false
}
```

If `AUTH_REQUIRE_EMAIL_VERIFICATION=true` and the user is not confirmed yet:

```json
{
  "result": {
    "error": true,
    "code": 106,
    "status": 403,
    "description": "Email is not confirmed",
    "name": "EMAIL_NOT_CONFIRMED",
    "additional": []
  },
  "error": true
}
```

#### `POST /login/refresh`

Refresh access token by refresh token.

```bash
curl -X POST "$API/login/refresh" \
  -H "Content-Type: application/json" \
  -d '{"refresh":"'"$REFRESH"'"}'
```

```json
{
  "result": {
    "id": 1,
    "email": "john@example.com",
    "phone": "+15550000001",
    "fullName": "John Doe",
    "role": "registered",
    "roles": ["registered"],
    "avatar": null,
    "locale": "en",
    "timezone": "UTC",
    "isEmailVerified": true,
    "isPhoneVerified": false,
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh": "Wm9Qd3J0Q..."
  },
  "error": false
}
```

#### `GET /login/refresh`

Same refresh flow, but the token is passed in query params.

```bash
curl "$API/login/refresh?refresh=$REFRESH"
```

Response is the same as `POST /login/refresh`.

#### `POST /login/forgot`

Generate and send password recovery code.

```bash
curl -X POST "$API/login/forgot" \
  -H "Content-Type: application/json" \
  -d '{"email":"john@example.com"}'
```

```json
{
  "result": {
    "ok": true
  },
  "error": false
}
```

#### `POST /login/restore`

Restore password by recovery code.

```bash
curl -X POST "$API/login/restore" \
  -H "Content-Type: application/json" \
  -d '{
    "code": "654321",
    "password": "new-secret-123"
  }'
```

```json
{
  "result": {
    "ok": true
  },
  "error": false
}
```

Wrong or expired code:

```json
{
  "result": {
    "error": true,
    "code": 108,
    "status": 409,
    "description": "Wrong code",
    "name": "WRONG_CODE",
    "additional": []
  },
  "error": true
}
```

#### `PATCH /login`

Authenticated self-update endpoint.

Supports:

- direct profile edits: `fullName`, `locale`, `timezone`
- password change: `password` + `newPassword`
- e-mail change request: `email`
- phone change request: `phone`

Request a new e-mail:

```bash
curl -X PATCH "$API/login" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"new-john@example.com"}'
```

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

Change password + profile data:

```bash
curl -X PATCH "$API/login" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "fullName": "John D.",
    "locale": "uk",
    "timezone": "Europe/Kyiv",
    "password": "secret-123",
    "newPassword": "secret-456"
  }'
```

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

#### `POST /login/email`

Confirm pending e-mail change by code.

```bash
curl -X POST "$API/login/email" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"code":"123456"}'
```

```json
{
  "result": {
    "id": 1,
    "email": "new-john@example.com",
    "phone": "+15550000001",
    "fullName": "John Doe",
    "role": "registered",
    "roles": ["registered"],
    "avatar": null,
    "locale": "en",
    "timezone": "UTC",
    "isEmailVerified": true,
    "isPhoneVerified": false,
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh": "Wm9Qd3J0Q..."
  },
  "error": false
}
```

#### `POST /login/email/confirm`

Alias of `POST /login/email`.

```bash
curl -X POST "$API/login/email/confirm" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"code":"123456"}'
```

Response is the same as `POST /login/email`.

#### `POST /login/email/resend`

Resend pending e-mail-change code, or resend registration confirmation code for the current unverified e-mail.

```bash
curl -X POST "$API/login/email/resend" \
  -H "Authorization: Bearer $TOKEN"
```

```json
{
  "result": {
    "ok": true
  },
  "error": false
}
```

#### `POST /login/phone`

Confirm phone or pending phone change by code.

```bash
curl -X POST "$API/login/phone" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"code":"123456"}'
```

```json
{
  "result": {
    "id": 1,
    "email": "john@example.com",
    "phone": "+15550000002",
    "fullName": "John Doe",
    "role": "registered",
    "roles": ["registered"],
    "avatar": null,
    "locale": "en",
    "timezone": "UTC",
    "isEmailVerified": true,
    "isPhoneVerified": true,
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh": "Wm9Qd3J0Q..."
  },
  "error": false
}
```

#### `POST /login/phone/confirm`

Alias of `POST /login/phone`.

```bash
curl -X POST "$API/login/phone/confirm" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"code":"123456"}'
```

Response is the same as `POST /login/phone`.

#### `POST /login/phone/resend`

Resend current phone confirmation code or pending phone-change code.

```bash
curl -X POST "$API/login/phone/resend" \
  -H "Authorization: Bearer $TOKEN"
```

```json
{
  "result": {
    "ok": true
  },
  "error": false
}
```

#### `GET /login/me`

Return current authenticated user.

```bash
curl "$API/login/me" \
  -H "Authorization: Bearer $TOKEN"
```

```json
{
  "result": {
    "id": 1,
    "email": "john@example.com",
    "phone": "+15550000001",
    "fullName": "John Doe",
    "role": "registered",
    "roles": ["registered"],
    "avatar": null,
    "locale": "en",
    "timezone": "UTC",
    "isEmailVerified": true,
    "isPhoneVerified": true,
    "permissionsHint": [
      "users.viewEmail",
      "users.viewPhone",
      "users.viewRole",
      "users.viewLocale",
      "users.viewStatus",
      "users.viewMeta"
    ],
    "ownerPermissionsHint": [
      "users.viewEmail",
      "users.viewPhone",
      "users.viewRole",
      "users.viewLocale",
      "users.viewMeta"
    ]
  },
  "error": false
}
```

### Users CRUD

#### `GET /users`

List users. Visibility of e-mail/phone/etc depends on permissions.

```bash
curl "$API/users?_sort=id" \
  -H "Authorization: Bearer $TOKEN"
```

Example for a user with only `users.get`:

```json
{
  "result": [
    {
      "id": 1,
      "timeCreated": "2026-03-14T10:00:00.000Z",
      "timeUpdated": null,
      "timeDeleted": null,
      "isBlocked": false,
      "isDeleted": false,
      "login": null,
      "isEmailVerified": true,
      "isEmailInvalid": false,
      "isPhoneVerified": true,
      "isPhoneInvalid": false,
      "fullName": "John Doe",
      "avatar": null,
      "role": "registered",
      "locale": "en",
      "timezone": "UTC"
    }
  ],
  "meta": {
    "total": 1,
    "limit": 0,
    "skip": 0,
    "page": 1,
    "pages": 1,
    "isFirstPage": true,
    "isLastPage": true
  },
  "error": false
}
```

#### `GET /users/:id`

Get one user. Owner permissions are applied when the token user matches the record id.

```bash
curl "$API/users/1" \
  -H "Authorization: Bearer $TOKEN"
```

Example for admin with `users.viewEmail` and `users.viewPhone`:

```json
{
  "result": {
    "id": 1,
    "timeCreated": "2026-03-14T10:00:00.000Z",
    "timeUpdated": "2026-03-14T10:05:00.000Z",
    "timeDeleted": null,
    "isBlocked": false,
    "isDeleted": false,
    "login": null,
    "email": "john@example.com",
    "isEmailVerified": true,
    "isEmailInvalid": false,
    "phone": "+15550000001",
    "isPhoneVerified": true,
    "isPhoneInvalid": false,
    "fullName": "John Doe",
    "avatar": null,
    "role": "registered",
    "locale": "en",
    "timezone": "UTC"
  },
  "error": false
}
```

#### `POST /users`

Create user through admin CRUD flow.

Fields are checked against route permissions and field edit permissions.

```bash
curl -X POST "$API/users" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "secret-123",
    "fullName": "New User",
    "phone": "+15550000003",
    "locale": "en",
    "timezone": "UTC",
    "role": "registered"
  }'
```

```json
{
  "result": {
    "id": 2,
    "timeCreated": "2026-03-14T10:15:00.000Z",
    "timeUpdated": null,
    "timeDeleted": null,
    "isBlocked": false,
    "isDeleted": false,
    "login": null,
    "email": "user@example.com",
    "isEmailVerified": false,
    "isEmailInvalid": false,
    "phone": "+15550000003",
    "isPhoneVerified": false,
    "isPhoneInvalid": false,
    "fullName": "New User",
    "avatar": null,
    "role": "registered",
    "locale": "en",
    "timezone": "UTC"
  },
  "error": false
}
```

#### `PATCH /users/:id`

Update user directly through admin CRUD flow.

Direct `email`/`phone` changes reset their verification state unless `isEmailVerified` / `isPhoneVerified` are explicitly set to `true` and the caller has `users.editVerification`.

```bash
curl -X PATCH "$API/users/2" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "updated-user@example.com",
    "fullName": "Updated User",
    "isEmailVerified": false
  }'
```

```json
{
  "result": {
    "id": 2,
    "timeCreated": "2026-03-14T10:15:00.000Z",
    "timeUpdated": "2026-03-14T10:20:00.000Z",
    "timeDeleted": null,
    "isBlocked": false,
    "isDeleted": false,
    "login": null,
    "email": "updated-user@example.com",
    "isEmailVerified": false,
    "isEmailInvalid": false,
    "phone": "+15550000003",
    "isPhoneVerified": false,
    "isPhoneInvalid": false,
    "fullName": "Updated User",
    "avatar": null,
    "role": "registered",
    "locale": "en",
    "timezone": "UTC"
  },
  "error": false
}
```

#### `DELETE /users/:id`

Soft-delete user.

```bash
curl -X DELETE "$API/users/2" \
  -H "Authorization: Bearer $TOKEN"
```

```json
{
  "result": {
    "ok": true
  },
  "error": false
}
```

#### `POST /users/:id/avatar`

Upload avatar. Owner or user with `users.patch` / `users.uploadAvatar` can do it.

```bash
curl -X POST "$API/users/1/avatar" \
  -H "Authorization: Bearer $TOKEN" \
  -F "avatar=@./avatar.png"
```

```json
{
  "result": {
    "id": 1,
    "timeCreated": "2026-03-14T10:00:00.000Z",
    "timeUpdated": "2026-03-14T10:30:00.000Z",
    "timeDeleted": null,
    "isBlocked": false,
    "isDeleted": false,
    "login": null,
    "email": "john@example.com",
    "isEmailVerified": true,
    "isEmailInvalid": false,
    "phone": "+15550000001",
    "isPhoneVerified": true,
    "isPhoneInvalid": false,
    "fullName": "John Doe",
    "avatar": "users/1/avatar/1a2b3c4d5e6f.png",
    "role": "registered",
    "locale": "en",
    "timezone": "UTC"
  },
  "error": false
}
```

#### `DELETE /users/:id/avatar`

Remove avatar.

```bash
curl -X DELETE "$API/users/1/avatar" \
  -H "Authorization: Bearer $TOKEN"
```

```json
{
  "result": {
    "id": 1,
    "timeCreated": "2026-03-14T10:00:00.000Z",
    "timeUpdated": "2026-03-14T10:35:00.000Z",
    "timeDeleted": null,
    "isBlocked": false,
    "isDeleted": false,
    "login": null,
    "email": "john@example.com",
    "isEmailVerified": true,
    "isEmailInvalid": false,
    "phone": "+15550000001",
    "isPhoneVerified": true,
    "isPhoneInvalid": false,
    "fullName": "John Doe",
    "avatar": null,
    "role": "registered",
    "locale": "en",
    "timezone": "UTC"
  },
  "error": false
}
```

## Development

Build:

```bash
bun run build
```

Run tests:

```bash
bun run test
```
