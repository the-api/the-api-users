import { expect, test } from 'bun:test';
import { verifiedOAuthIdentity } from '../src/lib/oauth';

test('unverified OAuth contact details cannot select an existing account', () => {
  const identity = verifiedOAuthIdentity({
    service: 'google',
    externalId: 'attacker',
    email: 'victim@example.com',
    emailVerified: false,
    phone: '+123456789',
    phoneVerified: false,
    rawProfile: {},
  });

  expect(identity.email).toBeNull();
  expect(identity.phone).toBeNull();
});
