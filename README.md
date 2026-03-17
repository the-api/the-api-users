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
import { roles } from 'the-api-roles';
import { login, users, migrationDir } from 'the-api-users';

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

Google supports:

- `accessToken`
- `idToken`
- `code`

Apple supports:

- `idToken`
- `code`

GitHub supports:

- `accessToken`
- `code`

Microsoft supports:

- `accessToken`
- `code`

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

### Linking to an existing logged-in user

```bash
curl -X POST "$API/login/github" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"accessToken":"github-access-token"}'
```

The response format is the same as normal login: the current user plus fresh `token` and `refresh`.

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
