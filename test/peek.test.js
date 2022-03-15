const chai = require('chai');
const jwt = require('jsonwebtoken');
const TokenIntrospection = require('../src/index');
const { assert } = chai;

describe('Peek into jwt', () => {
  it('returns null if tokens is not a JWT', () => {
    assert.isNull(TokenIntrospection.peek('xyz'));
  });

  it('returns header and body when valid', () => {
    const now = Date.now() / 1000;
    const accessTokenClaims = { exp: now + 5, iss: 'https://example.com' };
    const secretKey = 'super secret key';
    const accessToken = jwt.sign(accessTokenClaims, secretKey, { algorithm: 'HS256' });

    const data = TokenIntrospection.peek(accessToken);
    assert.hasAllKeys(data, ['header', 'payload', 'signature']);
    assert.equal(data.payload.iss, 'https://example.com');
  });
});
