import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { testClient } from 'the-api';

import { hashPassword, randomSalt } from '../src/lib/auth';
import { login } from '../src';

process.env.AUTH_GOOGLE_CLIENT_ID = 'google-client-id';
process.env.AUTH_GOOGLE_CLIENT_SECRET = 'google-client-secret';
process.env.AUTH_GOOGLE_REDIRECT_URI = 'https://app.test.local/auth/google/callback';
process.env.AUTH_GOOGLE_SCOPE = 'openid email profile';

process.env.AUTH_GITHUB_CLIENT_ID = 'github-client-id';
process.env.AUTH_GITHUB_CLIENT_SECRET = 'github-client-secret';
process.env.AUTH_GITHUB_REDIRECT_URI = 'https://app.test.local/auth/github/callback';
process.env.AUTH_GITHUB_SCOPE = 'read:user user:email';

process.env.AUTH_FACEBOOK_CLIENT_ID = 'facebook-client-id';
process.env.AUTH_FACEBOOK_CLIENT_SECRET = 'facebook-client-secret';
process.env.AUTH_FACEBOOK_REDIRECT_URI = 'https://app.test.local/auth/facebook/callback';
process.env.AUTH_FACEBOOK_SCOPE = 'email public_profile';

process.env.AUTH_LINKEDIN_CLIENT_ID = 'linkedin-client-id';
process.env.AUTH_LINKEDIN_CLIENT_SECRET = 'linkedin-client-secret';
process.env.AUTH_LINKEDIN_REDIRECT_URI = 'https://app.test.local/auth/linkedin/callback';
process.env.AUTH_LINKEDIN_SCOPE = 'openid profile email';

process.env.AUTH_MICROSOFT_CLIENT_ID = 'microsoft-client-id';
process.env.AUTH_MICROSOFT_CLIENT_SECRET = 'microsoft-client-secret';
process.env.AUTH_MICROSOFT_REDIRECT_URI = 'https://app.test.local/auth/microsoft/callback';
process.env.AUTH_MICROSOFT_SCOPE = 'openid profile email offline_access User.Read';
process.env.AUTH_MICROSOFT_TENANT_ID = 'common';

process.env.AUTH_TWITTER_CLIENT_ID = 'twitter-client-id';
process.env.AUTH_TWITTER_CLIENT_SECRET = 'twitter-client-secret';
process.env.AUTH_TWITTER_REDIRECT_URI = 'https://app.test.local/auth/twitter/callback';
process.env.AUTH_TWITTER_SCOPE = 'tweet.read users.read offline.access';

process.env.AUTH_APPLE_CLIENT_ID = 'apple-client-id';
process.env.AUTH_APPLE_CLIENT_SECRET = 'apple-client-secret';
process.env.AUTH_APPLE_REDIRECT_URI = 'https://app.test.local/auth/apple/callback';
process.env.AUTH_APPLE_SCOPE = 'name email';

const originalFetch = globalThis.fetch;
const appleKeyPair = generateKeyPairSync('rsa', { modulusLength: 2048 });
const applePrivateKey = createPrivateKey(appleKeyPair.privateKey.export({ format: 'pem', type: 'pkcs8' }));
const applePublicJwk = createPublicKey(appleKeyPair.publicKey.export({ format: 'pem', type: 'spki' }))
  .export({ format: 'jwk' });
const APPLE_KID = 'apple-test-key';

const jsonResponse = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });

const toBase64Url = (value: Buffer | string): string =>
  Buffer.from(value)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');

const createAppleIdToken = (payload: Record<string, unknown>): string => {
  const header = {
    alg: 'RS256',
    kid: APPLE_KID,
    typ: 'JWT',
  };
  const encodedHeader = toBase64Url(JSON.stringify(header));
  const encodedPayload = toBase64Url(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = cryptoSign('RSA-SHA256', Buffer.from(signingInput), applePrivateKey);
  return `${signingInput}.${toBase64Url(signature)}`;
};

const getBearerToken = (headers: HeadersInit | undefined): string => {
  if (!headers) return '';

  if (headers instanceof Headers) {
    return (headers.get('Authorization') || headers.get('authorization') || '')
      .replace(/^Bearer\s+/i, '');
  }

  if (Array.isArray(headers)) {
    const match = headers.find(([key]) => key.toLowerCase() === 'authorization');
    return (match?.[1] || '').replace(/^Bearer\s+/i, '');
  }

  return (headers.Authorization || headers.authorization || '').replace(/^Bearer\s+/i, '');
};

const oauthFetch: typeof fetch = async (input, init) => {
  const url = typeof input === 'string' ? input : input.url;
  const parsedUrl = new URL(url);

  if (url === 'https://www.googleapis.com/oauth2/v2/userinfo') {
    const token = getBearerToken(init?.headers);

    if (token === 'google-register-token') {
      return jsonResponse({
        id: 'google-user-1',
        email: 'oauth-new@test.local',
        verified_email: true,
        name: 'OAuth New',
        given_name: 'OAuth',
        family_name: 'New',
        picture: 'https://cdn.test/google-user-1.png',
        locale: 'en',
      });
    }

    if (token === 'google-existing-token') {
      return jsonResponse({
        id: 'google-user-2',
        email: 'oauth-match@test.local',
        verified_email: true,
        name: 'Existing Match',
        given_name: 'Existing',
        family_name: 'Match',
        picture: 'https://cdn.test/google-user-2.png',
        locale: 'uk',
      });
    }

    if (token === 'google-login-collision-token') {
      return jsonResponse({
        id: 'google-user-login-collision',
        email: 'collision-user@test.local',
        verified_email: true,
        name: 'Collision User',
        given_name: 'Collision',
        family_name: 'User',
        picture: 'https://cdn.test/google-user-login-collision.png',
        locale: 'en',
      });
    }

    return jsonResponse({ error: 'invalid_token' }, 401);
  }

  if (parsedUrl.origin === 'https://graph.facebook.com' && parsedUrl.pathname === '/v18.0/me') {
    const token = parsedUrl.searchParams.get('access_token') || '';

    if (token === 'facebook-register-token') {
      return jsonResponse({
        id: 'facebook-user-1',
        email: 'facebook-new@test.local',
        first_name: 'Facebook',
        last_name: 'User',
        name: 'Facebook User',
        picture: {
          data: {
            url: 'https://cdn.test/facebook-user-1.png',
          },
        },
      });
    }

    return jsonResponse({ error: { message: 'Invalid OAuth access token.' } }, 401);
  }

  if (url === 'https://api.github.com/user') {
    const token = getBearerToken(init?.headers);

    if (token === 'github-link-token') {
      return new Response(JSON.stringify({
        id: 5001,
        login: 'linked-gh-user',
        name: 'Linked GitHub User',
        avatar_url: 'https://cdn.test/github-user-1.png',
        email: null,
      }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'x-oauth-scopes': 'read:user, user:email',
        },
      });
    }

    return jsonResponse({ message: 'Bad credentials' }, 401);
  }

  if (url === 'https://api.linkedin.com/v2/userinfo') {
    const token = getBearerToken(init?.headers);

    if (token === 'linkedin-register-token') {
      return jsonResponse({
        sub: 'linkedin-user-1',
        email: 'linkedin-new@test.local',
        email_verified: true,
        name: 'LinkedIn User',
        given_name: 'LinkedIn',
        family_name: 'User',
        picture: 'https://cdn.test/linkedin-user-1.png',
        locale: 'en-US',
      });
    }

    return jsonResponse({ message: 'Invalid access token' }, 401);
  }

  if (url === 'https://graph.microsoft.com/v1.0/me?$select=id,displayName,givenName,surname,mail,userPrincipalName') {
    const token = getBearerToken(init?.headers);

    if (token === 'microsoft-register-token') {
      return jsonResponse({
        id: 'microsoft-user-1',
        displayName: 'Microsoft User',
        givenName: 'Microsoft',
        surname: 'User',
        mail: 'microsoft-new@test.local',
        userPrincipalName: 'microsoft-new@test.local',
      });
    }

    return jsonResponse({ error: { code: 'InvalidAuthenticationToken' } }, 401);
  }

  if (url === 'https://api.github.com/user/emails') {
    const token = getBearerToken(init?.headers);

    if (token === 'github-link-token') {
      return jsonResponse([
        {
          email: 'oauth-secondary@test.local',
          primary: true,
          verified: true,
        },
      ]);
    }

    return jsonResponse({ message: 'Bad credentials' }, 401);
  }

  if (parsedUrl.origin === 'https://api.twitter.com' && parsedUrl.pathname === '/2/users/me') {
    const token = getBearerToken(init?.headers);

    if (token === 'twitter-link-token') {
      return jsonResponse({
        data: {
          id: 'twitter-user-1',
          name: 'Twitter Linked User',
          username: 'twitter-linked-user',
          profile_image_url: 'https://cdn.test/twitter-user-1.png',
        },
      });
    }

    return jsonResponse({ error: 'invalid_token' }, 401);
  }

  if (url === 'https://appleid.apple.com/auth/keys') {
    return jsonResponse({
      keys: [
        {
          ...applePublicJwk,
          kid: APPLE_KID,
          use: 'sig',
          alg: 'RS256',
        },
      ],
    });
  }

  return originalFetch(input, init);
};

const { theAPI, client } = await testClient({
  migrationDirs: ['./migrations'],
  routings: [login],
});

beforeAll(() => {
  globalThis.fetch = oauthFetch;
});

afterAll(() => {
  globalThis.fetch = originalFetch;
});

describe('OAuth', () => {
  let linkedUserToken = '';
  let linkedUserId = 0;

  test('GET /login/google redirects to Google OAuth server', async () => {
    const response = await theAPI.app.fetch(new Request('http://localhost:7788/login/google'));
    const location = response.headers.get('location') || '';
    const url = new URL(location);

    expect(response.status).toEqual(302);
    expect(url.origin + url.pathname).toEqual('https://accounts.google.com/o/oauth2/v2/auth');
    expect(url.searchParams.get('client_id')).toEqual('google-client-id');
    expect(url.searchParams.get('redirect_uri')).toEqual('https://app.test.local/auth/google/callback');
    expect(url.searchParams.get('scope')).toEqual('openid email profile');
    expect(typeof url.searchParams.get('state')).toEqual('string');
  });

  test('GET /login/twitter redirects to X OAuth server with PKCE challenge', async () => {
    const response = await theAPI.app.fetch(new Request('http://localhost:7788/login/twitter'));
    const location = response.headers.get('location') || '';
    const url = new URL(location);

    expect(response.status).toEqual(302);
    expect(url.origin + url.pathname).toEqual('https://x.com/i/oauth2/authorize');
    expect(url.searchParams.get('client_id')).toEqual('twitter-client-id');
    expect(url.searchParams.get('redirect_uri')).toEqual('https://app.test.local/auth/twitter/callback');
    expect(url.searchParams.get('scope')).toEqual('tweet.read users.read offline.access');
    expect(url.searchParams.get('code_challenge_method')).toEqual('S256');
    expect(typeof url.searchParams.get('code_challenge')).toEqual('string');
  });

  test('GET /login/apple redirects to Apple OAuth server', async () => {
    const response = await theAPI.app.fetch(new Request('http://localhost:7788/login/apple'));
    const location = response.headers.get('location') || '';
    const url = new URL(location);

    expect(response.status).toEqual(302);
    expect(url.origin + url.pathname).toEqual('https://appleid.apple.com/auth/authorize');
    expect(url.searchParams.get('client_id')).toEqual('apple-client-id');
    expect(url.searchParams.get('redirect_uri')).toEqual('https://app.test.local/auth/apple/callback');
    expect(url.searchParams.get('response_mode')).toEqual('form_post');
    expect(url.searchParams.get('scope')).toEqual('name email');
  });

  test('GET /login/microsoft redirects to Microsoft OAuth server', async () => {
    const response = await theAPI.app.fetch(new Request('http://localhost:7788/login/microsoft'));
    const location = response.headers.get('location') || '';
    const url = new URL(location);

    expect(response.status).toEqual(302);
    expect(url.origin + url.pathname).toEqual('https://login.microsoftonline.com/common/oauth2/v2.0/authorize');
    expect(url.searchParams.get('client_id')).toEqual('microsoft-client-id');
    expect(url.searchParams.get('redirect_uri')).toEqual('https://app.test.local/auth/microsoft/callback');
    expect(url.searchParams.get('scope')).toEqual('openid profile email offline_access User.Read');
  });

  test('POST /login/google registers a new user and stores OAuth profile', async () => {
    const { result } = await client.post('/login/google', { accessToken: 'google-register-token' });
    const user = await client.db('users').where({ email: 'oauth-new@test.local' }).first();

    expect(result.email).toEqual('oauth-new@test.local');
    expect(result.role).toEqual('registered');
    expect(result.isEmailVerified).toEqual(true);
    expect(result.oauthServices).toEqual(['google']);
    expect(typeof result.token).toEqual('string');
    expect(typeof result.refresh).toEqual('string');

    expect(user.password).toEqual(null);
    expect(user.salt).toEqual(null);
    expect(user.isEmailVerified).toEqual(true);
    expect(user.role).toEqual('registered');
    expect(user.login).toMatch(/^oauth-new\d+$/);
    expect(user.oauthProviders.google.externalId).toEqual('google-user-1');
  });

  test('POST /login/google increments OAuth login number until it is unique', async () => {
    await client.db('users').insert({
      login: 'collision-user1000',
      email: 'collision-login-existing@test.local',
      isEmailVerified: true,
      role: 'registered',
    });

    const originalRandom = Math.random;
    Math.random = () => 0.1;

    try {
      const { result } = await client.post('/login/google', { accessToken: 'google-login-collision-token' });
      const user = await client.db('users').where({ email: 'collision-user@test.local' }).first();

      expect(result.email).toEqual('collision-user@test.local');
      expect(user.login).toEqual('collision-user2000');
    } finally {
      Math.random = originalRandom;
    }
  });

  test('POST /login/facebook registers a new user', async () => {
    const { result } = await client.post('/login/facebook', { accessToken: 'facebook-register-token' });
    const user = await client.db('users').where({ email: 'facebook-new@test.local' }).first();

    expect(result.email).toEqual('facebook-new@test.local');
    expect(result.role).toEqual('registered');
    expect(result.oauthServices).toEqual(['facebook']);
    expect(user.oauthProviders.facebook.externalId).toEqual('facebook-user-1');
  });

  test('POST /login/linkedin registers a new user', async () => {
    const { result } = await client.post('/login/linkedin', { accessToken: 'linkedin-register-token' });
    const user = await client.db('users').where({ email: 'linkedin-new@test.local' }).first();

    expect(result.email).toEqual('linkedin-new@test.local');
    expect(result.role).toEqual('registered');
    expect(result.oauthServices).toEqual(['linkedin']);
    expect(user.oauthProviders.linkedin.externalId).toEqual('linkedin-user-1');
  });

  test('POST /login/microsoft registers a new user', async () => {
    const { result } = await client.post('/login/microsoft', { accessToken: 'microsoft-register-token' });
    const user = await client.db('users').where({ email: 'microsoft-new@test.local' }).first();

    expect(result.email).toEqual('microsoft-new@test.local');
    expect(result.role).toEqual('registered');
    expect(result.isEmailVerified).toEqual(true);
    expect(result.oauthServices).toEqual(['microsoft']);
    expect(user.oauthProviders.microsoft.externalId).toEqual('microsoft-user-1');
  });

  test('POST /login/apple accepts form_post payload and registers a new user', async () => {
    const now = Math.floor(Date.now() / 1000);
    const idToken = createAppleIdToken({
      iss: 'https://appleid.apple.com',
      aud: 'apple-client-id',
      exp: now + 3600,
      iat: now,
      sub: 'apple-user-1',
      email: 'apple-new@test.local',
      email_verified: true,
    });

    const response = await theAPI.app.fetch(new Request('http://localhost:7788/login/apple', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        id_token: idToken,
        user: JSON.stringify({
          name: {
            firstName: 'Apple',
            lastName: 'User',
          },
        }),
      }),
    }));
    const body = await response.json();
    const user = await client.db('users').where({ email: 'apple-new@test.local' }).first();

    expect(response.status).toEqual(200);
    expect(body.result.email).toEqual('apple-new@test.local');
    expect(body.result.role).toEqual('registered');
    expect(body.result.isEmailVerified).toEqual(true);
    expect(body.result.oauthServices).toEqual(['apple']);
    expect(user.oauthProviders.apple.externalId).toEqual('apple-user-1');
    expect(user.fullName).toEqual('Apple User');
  });

  test('POST /login/google matches existing unverified user by email and upgrades verification', async () => {
    await client.post('/login/register', {
      email: 'oauth-match@test.local',
      password: 'oauth-match-pass',
      fullName: 'Needs Upgrade',
    });

    const before = await client.db('users').where({ email: 'oauth-match@test.local' }).first();
    const { result } = await client.post('/login/google', { accessToken: 'google-existing-token' });
    const after = await client.db('users').where({ email: 'oauth-match@test.local' }).first();

    expect(result.id).toEqual(before.id);
    expect(result.role).toEqual('registered');
    expect(result.isEmailVerified).toEqual(true);
    expect(result.oauthServices).toEqual(['google']);

    expect(after.id).toEqual(before.id);
    expect(after.role).toEqual('registered');
    expect(after.isEmailVerified).toEqual(true);
    expect(after.oauthProviders.google.externalId).toEqual('google-user-2');
  });

  test('POST /login/github with our auth token links provider to current user', async () => {
    const salt = randomSalt();
    const password = 'linked-pass';
    const passwordHash = hashPassword(password, salt);

    const [linkedUser] = await client.db('users')
      .insert({
        email: 'linked-user@test.local',
        password: passwordHash,
        salt,
        fullName: 'Linked User',
        role: 'registered',
        isEmailVerified: true,
        refresh: 'linked-refresh',
        timeRefreshExpired: new Date(0),
      })
      .returning('*');

    linkedUserId = linkedUser.id;

    const loginResult = await client.post('/login', {
      email: 'linked-user@test.local',
      password,
    });
    linkedUserToken = loginResult.result.token;

    const { result } = await client.post('/login/github', {
      accessToken: 'github-link-token',
    }, linkedUserToken);
    const linkedRecord = await client.db('users').where({ id: linkedUserId }).first();

    expect(result.id).toEqual(linkedUserId);
    expect(result.email).toEqual('linked-user@test.local');
    expect(result.oauthServices).toEqual(['github']);

    expect(linkedRecord.email).toEqual('linked-user@test.local');
    expect(linkedRecord.oauthProviders.github.externalId).toEqual('5001');
    expect(linkedRecord.oauthProviders.github.email).toEqual('oauth-secondary@test.local');
  });

  test('GET /login/externals returns linked services for current user', async () => {
    const { result } = await client.get('/login/externals', linkedUserToken);

    expect(result).toHaveLength(1);
    expect(result[0].service).toEqual('github');
    expect(result[0].email).toEqual('oauth-secondary@test.local');
  });

  test('DELETE /login/github removes provider data from user', async () => {
    const { result } = await client.delete('/login/github', linkedUserToken);
    const linkedRecord = await client.db('users').where({ id: linkedUserId }).first();

    expect(result.ok).toEqual(true);
    expect(result.oauthServices).toEqual([]);
    expect(linkedRecord.oauthProviders?.github).toEqual(undefined);
  });

  test('POST /login/twitter links provider without changing primary email', async () => {
    const { result } = await client.post('/login/twitter', {
      accessToken: 'twitter-link-token',
    }, linkedUserToken);
    const linkedRecord = await client.db('users').where({ id: linkedUserId }).first();

    expect(result.id).toEqual(linkedUserId);
    expect(result.email).toEqual('linked-user@test.local');
    expect(result.oauthServices).toEqual(['twitter']);
    expect(linkedRecord.email).toEqual('linked-user@test.local');
    expect(linkedRecord.oauthProviders.twitter.externalId).toEqual('twitter-user-1');
  });

  test('GET and POST /login/google return 404 when provider config is missing', async () => {
    const originalClientSecret = process.env.AUTH_GOOGLE_CLIENT_SECRET;

    delete process.env.AUTH_GOOGLE_CLIENT_SECRET;

    try {
      const getResponse = await theAPI.app.fetch(new Request('http://localhost:7788/login/google'));
      const getBody = await getResponse.json();

      expect(getResponse.status).toEqual(404);
      expect(getBody.result.code).toEqual(118);
      expect(getBody.result.name).toEqual('OAUTH_SERVICE_NOT_SUPPORTED');

      const postResponse = await theAPI.app.fetch(new Request('http://localhost:7788/login/google', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          accessToken: 'google-register-token',
        }),
      }));
      const postBody = await postResponse.json();

      expect(postResponse.status).toEqual(404);
      expect(postBody.result.code).toEqual(118);
      expect(postBody.result.name).toEqual('OAUTH_SERVICE_NOT_SUPPORTED');
    } finally {
      process.env.AUTH_GOOGLE_CLIENT_SECRET = originalClientSecret;
    }
  });
});
