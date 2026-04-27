# the-api-users

Users and authentication module for `the-api`.

It ships with:

- e-mail registration and confirmation
- password login with access token + refresh token
- refresh, password recovery, e-mail change and phone verification flows
- users CRUD with field-level visibility/edit permissions
- avatar upload
- OAuth login/link/unlink without `passport`
- automatic OAuth account linking by provider id, e-mail and phone

Supported OAuth providers in this package:

- Apple
- Facebook
- Google
- GitHub
- LinkedIn
- Microsoft
- Twitter/X

`oauthProviders` are stored in the `users` table as `jsonb`. The implementation is tested with PostgreSQL.

## Installation

```bash
npm i the-api-users
```

## Quick Start

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

## Environment

See [.env.example](./.env.example).

Core auth variables:

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
- `AUTH_PASSWORD_HASH_ALGORITHM` (`scrypt` by default, or `sha256`)
- `AUTH_SCRYPT_N` (`16384` by default, must be a power of two)
- `AUTH_SCRYPT_R` (`8` by default)
- `AUTH_SCRYPT_P` (`1` by default)
- `AUTH_SCRYPT_MAXMEM` (`33554432` by default)

Google OAuth:

- `AUTH_GOOGLE_CLIENT_ID`
- `AUTH_GOOGLE_CLIENT_SECRET`
- `AUTH_GOOGLE_REDIRECT_URI`
- `AUTH_GOOGLE_SCOPE`
- `AUTH_GOOGLE_ACCESS_TYPE`
- `AUTH_GOOGLE_PROMPT`

GitHub OAuth:

- `AUTH_GITHUB_CLIENT_ID`
- `AUTH_GITHUB_CLIENT_SECRET`
- `AUTH_GITHUB_REDIRECT_URI`
- `AUTH_GITHUB_SCOPE`

Facebook OAuth:

- `AUTH_FACEBOOK_CLIENT_ID`
- `AUTH_FACEBOOK_CLIENT_SECRET`
- `AUTH_FACEBOOK_REDIRECT_URI`
- `AUTH_FACEBOOK_SCOPE`
- `AUTH_FACEBOOK_FIELDS`

LinkedIn OAuth:

- `AUTH_LINKEDIN_CLIENT_ID`
- `AUTH_LINKEDIN_CLIENT_SECRET`
- `AUTH_LINKEDIN_REDIRECT_URI`
- `AUTH_LINKEDIN_SCOPE`

Microsoft OAuth:

- `AUTH_MICROSOFT_CLIENT_ID`
- `AUTH_MICROSOFT_CLIENT_SECRET`
- `AUTH_MICROSOFT_REDIRECT_URI`
- `AUTH_MICROSOFT_SCOPE`
- `AUTH_MICROSOFT_TENANT_ID`

Twitter/X OAuth:

- `AUTH_TWITTER_CLIENT_ID`
- `AUTH_TWITTER_CLIENT_SECRET`
- `AUTH_TWITTER_REDIRECT_URI`
- `AUTH_TWITTER_SCOPE`
- `AUTH_TWITTER_FIELDS`

Apple OAuth:

- `AUTH_APPLE_CLIENT_ID`
- `AUTH_APPLE_CLIENT_SECRET`
- `AUTH_APPLE_REDIRECT_URI`
- `AUTH_APPLE_SCOPE`
- `AUTH_APPLE_TEAM_ID`
- `AUTH_APPLE_KEY_ID`
- `AUTH_APPLE_PRIVATE_KEY`

Storage / delivery:

- `EMAIL_*`
- `SMS_PROVIDER`, `TWILIO_*`
- `FILES_FOLDER` or `MINIO_*`

Notes:

- Legacy aliases `AUTH_GOOGLE_CALLBACK_URL` and `AUTH_GITHUB_CALLBACK_URL` are also accepted.
- GitHub login should request `user:email`, otherwise the provider may not return a usable e-mail.
- Apple can use either a pre-generated `AUTH_APPLE_CLIENT_SECRET` or dynamic secret generation via `AUTH_APPLE_TEAM_ID` + `AUTH_APPLE_KEY_ID` + `AUTH_APPLE_PRIVATE_KEY`.
- Apple browser callbacks use `response_mode=form_post`, so your frontend callback should accept form posts or forward the received fields to `POST /login/apple`.
- Microsoft Entra ID login uses the v2 endpoint and defaults to tenant `common` unless `AUTH_MICROSOFT_TENANT_ID` is set.
- If a provider is not fully configured with required `AUTH_*` variables, `GET /login/{service}` and `POST /login/{service}` respond with `404` the same way as an unavailable provider.
- Twitter/X usually does not return e-mail in the standard OAuth profile. First-time sign-in will work only if the provider returns a usable e-mail/phone or if the request is linking to an already authenticated user.
- Use HTTPS in production and register the exact redirect URIs in the provider console.
- Set `AUTH_PASSWORD_HASH_ALGORITHM=sha256` only if you want to store `sha256(password + salt)` password hashes. New password inserts and updates will use the selected algorithm too.
- `AUTH_SCRYPT_*` values are used only when `AUTH_PASSWORD_HASH_ALGORITHM=scrypt`. Changing them changes the generated hash, so existing passwords continue to work only if they were created with the same parameters or rehashed.

## OAuth Behavior

One service uses one endpoint pair:

- `GET /login/google`
- `POST /login/google`
- `DELETE /login/google`

Same for `github`.
Same for `apple`, `facebook`, `linkedin`, `microsoft` and `twitter`.

Rules implemented by the module:

- If the provider account is already linked, the user gets normal `token` + `refresh`.
- If the provider returns an e-mail or phone that belongs to an existing user, that user is logged in and the provider is linked automatically.
- If no user exists, a new user is created with `password = null` and `salt = null`.
- If OAuth returns e-mail or phone, that identity is treated as verified.
- If the user role was `unverified`, it is promoted to `registered`.
- If `Authorization: Bearer <our-token>` is sent to `POST /login/{service}`, the provider is linked to the current user.
- `DELETE /login/{service}` removes provider data from `users.oauthProviders`.
- The last available login method cannot be unlinked if the user has no local password.

Stored provider payload includes the provider user id, basic profile fields, scopes and timestamps. Provider access tokens are not persisted in `users`.

## OAuth Flows

### Browser redirect flow

1. Redirect the user to `GET /login/google`, `GET /login/apple`, `GET /login/microsoft` or another provider endpoint.
2. Provider redirects to your configured `AUTH_*_REDIRECT_URI`.
3. Your frontend callback receives provider `code` and `state`.
4. Frontend sends them to `POST /login/{service}` and receives your API `token` + `refresh`.

Google example:

```bash
curl -X POST "$API/login/google" \
  -H "Content-Type: application/json" \
  -d '{
    "code": "provider-auth-code",
    "state": "provider-state-from-callback"
  }'
```

GitHub example:

```bash
curl -X POST "$API/login/github" \
  -H "Content-Type: application/json" \
  -d '{
    "code": "provider-auth-code",
    "state": "provider-state-from-callback"
  }'
```

### Direct token flow

Useful for native/mobile/SPA flows where the client already has a provider token.

Supported request payloads:

- Google: `accessToken`, `idToken` or `code`
- Apple: `idToken` or `code`
- GitHub: `accessToken` or `code`
- Facebook: `accessToken` or `code`
- LinkedIn: `accessToken` or `code`
- Microsoft: `accessToken` or `code`
- Twitter/X: `accessToken` or `code`

Twitter/X authorization-code exchange uses PKCE, so it needs the `codeVerifier` saved by `GET /login/twitter` or an explicit `codeVerifier` / `code_verifier` in the request body.

Examples:

```bash
curl -X POST "$API/login/google" \
  -H "Content-Type: application/json" \
  -d '{"accessToken":"google-access-token"}'
```

```bash
curl -X POST "$API/login/github" \
  -H "Content-Type: application/json" \
  -d '{"accessToken":"github-access-token"}'
```

```bash
curl -X POST "$API/login/facebook" \
  -H "Content-Type: application/json" \
  -d '{"accessToken":"facebook-access-token"}'
```

```bash
curl -X POST "$API/login/linkedin" \
  -H "Content-Type: application/json" \
  -d '{"accessToken":"linkedin-access-token"}'
```

```bash
curl -X POST "$API/login/microsoft" \
  -H "Content-Type: application/json" \
  -d '{"accessToken":"microsoft-access-token"}'
```

Apple `form_post` callbacks can be forwarded as URL-encoded form data:

```bash
curl -X POST "$API/login/apple" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "id_token=apple-id-token" \
  --data-urlencode 'user={"name":{"firstName":"Apple","lastName":"User"}}'
```

### Linking to an existing logged-in user

```bash
curl -X POST "$API/login/github" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"accessToken":"github-access-token"}'
```

The response format is the same as normal login: the current user plus fresh `token` and `refresh`.

Twitter/X usually does not return e-mail; use it as a linking flow unless your provider response includes a usable e-mail or phone:

```bash
curl -X POST "$API/login/twitter" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"accessToken":"twitter-access-token"}'
```

### Listing and unlinking linked providers

```bash
curl -H "Authorization: Bearer $TOKEN" "$API/login/externals"
```

```bash
curl -X DELETE -H "Authorization: Bearer $TOKEN" "$API/login/github"
```

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

Successful auth responses include:

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
    "oauthServices": ["google"],
    "token": "jwt...",
    "refresh": "refresh-token..."
  },
  "error": false
}
```

Refresh token behavior:

- A successful login reuses the current refresh token while it is not expired.
- If the stored refresh token is expired, password/OAuth login rotates it and returns a new one.
- `POST /login/refresh` and `GET /login/refresh` keep the same refresh token and extend its expiry.
- Password restore and user deletion invalidate existing refresh tokens by replacing them with an expired token.

## Request Examples

The examples below follow the flows covered by the test suite. Use these placeholders:

```bash
API="http://localhost:7788"
TOKEN="jwt-from-login"
REFRESH="refresh-token-from-login"
ADMIN_TOKEN="admin-jwt"
USER_ID="1"
```

`TOKEN` is `result.token` from an auth response. `REFRESH` is `result.refresh`.

### Flow map

- New password user: `POST /login/register` -> `POST /login/register/confirm` -> `POST /login`.
- Existing password user: `POST /login` -> `POST /login/refresh` or `GET /login/refresh`.
- Forgotten password: `POST /login/forgot` -> `POST /login/restore` -> `POST /login`.
- Own account changes: `PATCH /login`; confirm e-mail through `/login/email`, confirm phone through `/login/phone`.
- Admin user management: `/users` endpoints with route and field permissions.
- OAuth user: `GET /login/{service}` -> provider callback -> `POST /login/{service}`, or direct token `POST /login/{service}`.

### Registration with e-mail confirmation

```bash
curl -X POST "$API/login/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "auth-user-1@test.local",
    "password": "auth-pass-1",
    "fullName": "Auth User",
    "locale": "en",
    "timezone": "UTC"
  }'
```

With `AUTH_REQUIRE_EMAIL_VERIFICATION=true`, the user is created as `unverified` and the response includes:

```json
{
  "result": {
    "ok": true,
    "email": "auth-user-1@test.local",
    "role": "unverified",
    "refresh": "refresh-token...",
    "emailConfirmationRequired": true
  }
}
```

Before confirmation, password login and refresh return `EMAIL_NOT_CONFIRMED`. After confirmation, the normal auth response includes a JWT and the same unexpired refresh token.

```bash
curl -X POST "$API/login/register/confirm" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "auth-user-1@test.local",
    "code": "code-from-email"
  }'
```

`POST /login/register/check` is an alias for the same confirmation flow. Use this to send a fresh code:

```bash
curl -X POST "$API/login/register/resend" \
  -H "Content-Type: application/json" \
  -d '{"email":"auth-user-1@test.local"}'
```

If `AUTH_REQUIRE_EMAIL_VERIFICATION` is not `true`, `POST /login/register` returns the normal auth response with `token` and `refresh` immediately.

### Password login and refresh

```bash
curl -X POST "$API/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "auth-user-1@test.local",
    "password": "auth-pass-1"
  }'
```

You can also log in with `login` instead of `email` when the user has a login name:

```bash
curl -X POST "$API/login" \
  -H "Content-Type: application/json" \
  -d '{
    "login": "auth-user",
    "password": "auth-pass-1"
  }'
```

Refresh keeps the same refresh token and returns a fresh JWT:

```bash
curl -X POST "$API/login/refresh" \
  -H "Content-Type: application/json" \
  -d '{"refresh":"refresh-token-from-login"}'
```

```bash
curl "$API/login/refresh?refresh=refresh-token-from-login"
```

Password or OAuth login also keeps the current refresh token until it expires. If the stored refresh token has expired, login rotates it and returns the replacement.

Current logged-in user:

```bash
curl -H "Authorization: Bearer $TOKEN" "$API/login/me"
```

### Password recovery

Request a recovery code. The response is `{ "ok": true }` even when the e-mail is unknown.

```bash
curl -X POST "$API/login/forgot" \
  -H "Content-Type: application/json" \
  -d '{"email":"auth-user-1@test.local"}'
```

Set a new password with the code from e-mail:

```bash
curl -X POST "$API/login/restore" \
  -H "Content-Type: application/json" \
  -d '{
    "code": "recover-code-from-email",
    "password": "auth-pass-2"
  }'
```

After restore, existing refresh tokens are invalidated. Log in with the new password to receive a new active refresh token.

### Own profile, password, e-mail and phone

Update self-editable profile fields:

```bash
curl -X PATCH "$API/login" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "fullName": "Updated User",
    "locale": "uk",
    "timezone": "Europe/Kyiv"
  }'
```

Change password by sending the current password as `password` and the replacement as `newPassword`:

```bash
curl -X PATCH "$API/login" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "password": "auth-pass-2",
    "newPassword": "auth-pass-3"
  }'
```

Request an e-mail change:

```bash
curl -X PATCH "$API/login" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"auth-user-1-updated@test.local"}'
```

The response includes `emailChangeRequested: true`. Confirm it with the code sent to the new e-mail:

```bash
curl -X POST "$API/login/email" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"code":"email-change-code"}'
```

`POST /login/email/confirm` is an alias. Use `POST /login/email/resend` with the same bearer token to send a fresh code.

Request and confirm a phone change:

```bash
curl -X PATCH "$API/login" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"phone":"+15550000001"}'
```

```bash
curl -X POST "$API/login/phone" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"code":"phone-change-code"}'
```

`POST /login/phone/confirm` is an alias. Use `POST /login/phone/resend` to send a fresh code.

### Users CRUD and avatar

The `/users` module is permission-based. A token with only `users.get` can list users but private fields such as `email`, `phone`, `password`, `salt` and auth codes are hidden. The owner gets the visibility permissions listed in `USER_OWNER_PERMISSIONS` for their own record. Admin-like roles need route permissions plus field permissions such as `users.viewEmail`, `users.editEmail` and `users.editVerification`.

Create a user as an admin:

```bash
curl -X POST "$API/users" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user-1@test.local",
    "password": "pass-1",
    "fullName": "User One",
    "locale": "uk",
    "timezone": "Europe/Kyiv"
  }'
```

List users, sorted by id:

```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" "$API/users?_sort=id"
```

Read one user:

```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" "$API/users/$USER_ID"
```

Patch fields allowed by the caller's field permissions:

```bash
curl -X PATCH "$API/users/$USER_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user-1-updated@test.local",
    "fullName": "Updated User",
    "isEmailVerified": false
  }'
```

When an admin changes e-mail and sets `isEmailVerified: false`, the module generates a new register code and keeps non-`unverified` roles unchanged.

Upload or replace an avatar. The owner, `users.patch` or `users.uploadAvatar` can do this:

```bash
curl -X POST "$API/users/$USER_ID/avatar" \
  -H "Authorization: Bearer $TOKEN" \
  -F "avatar=@tests/static/1.png"
```

Delete a user as an admin:

```bash
curl -X DELETE "$API/users/$USER_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

Deleting a user also invalidates their stored refresh token.

### Error handling

Errors use the same response envelope. Branch on `result.name`; examples covered by the tests include `EMAIL_NOT_CONFIRMED`, `WRONG_CODE`, `INVALID_OR_EXPIRED_CODE`, `ACCESS_DENIED`, `NOT_FOUND` and `OAUTH_SERVICE_NOT_SUPPORTED`.

## Main Endpoints

Auth:

- `POST /login/register`
- `POST /login/register/confirm`
- `POST /login/register/check`
- `POST /login/register/resend`
- `POST /login`
- `POST /login/refresh`
- `GET /login/refresh`
- `POST /login/forgot`
- `POST /login/restore`
- `PATCH /login`
- `POST /login/email`
- `POST /login/email/confirm`
- `POST /login/email/resend`
- `POST /login/phone`
- `POST /login/phone/confirm`
- `POST /login/phone/resend`
- `GET /login/me`
- `GET /login/externals`
- `GET /login/apple`
- `POST /login/apple`
- `DELETE /login/apple`
- `GET /login/google`
- `POST /login/google`
- `DELETE /login/google`
- `GET /login/github`
- `POST /login/github`
- `DELETE /login/github`
- `GET /login/facebook`
- `POST /login/facebook`
- `DELETE /login/facebook`
- `GET /login/linkedin`
- `POST /login/linkedin`
- `DELETE /login/linkedin`
- `GET /login/microsoft`
- `POST /login/microsoft`
- `DELETE /login/microsoft`
- `GET /login/twitter`
- `POST /login/twitter`
- `DELETE /login/twitter`

Users CRUD:

- `GET /users`
- `GET /users/:id`
- `POST /users`
- `PATCH /users/:id`
- `DELETE /users/:id`
- `POST /users/:id/avatar`
- `DELETE /users/:id/avatar`

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

## Data Model Notes

`users` now contains OAuth metadata:

- `password`: nullable for OAuth-created users
- `salt`: nullable for OAuth-created users
- `email`: nullable for OAuth users created from a verified phone-only identity
- `refresh`: generated for password and OAuth users; expired values are replaced on the next successful login
- `timeRefreshExpired`: controls refresh validity and is set to an already expired date when refresh access is intentionally invalidated
- `oauthProviders`: `jsonb` map keyed by service name

Each provider record stores:

- `service`
- `externalId`
- `email`
- `phone`
- `fullName`
- `avatar`
- `grantedScopes`
- `linkedAt`
- `updatedAt`
- `profile`

## Development

Run tests:

```bash
bun run test
```

Build the package:

```bash
bun run build
```
