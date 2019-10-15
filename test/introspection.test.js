const fs = require('fs');
const chai = require('chai');
const chaiAsPromised = require('chai-as-promised');
const nock = require('nock');
const jwt = require('jsonwebtoken');
const { pem2jwk } = require('pem-jwk');
const TokenIntrospection = require('../src/index');

const { assert, expect } = chai;
chai.use(chaiAsPromised);
nock.disableNetConnect();

const keyId = 'test_key_id';
function setupJwks() {
  const publicKey = fs.readFileSync('./test/public.pem', 'ascii');
  const jwk = pem2jwk(publicKey);
  return { keys: [{ kid: keyId, use: 'sig', ...jwk }] };
}
const privateKey = fs.readFileSync('./test/private.pem', 'ascii');
const jwks = setupJwks(keyId);
const jwksUri = 'http://example.com/jwks';

describe('Configuration', () => {
  it('throws error if required config is missing', () => expect(() => TokenIntrospection()).to.throw(Error, 'must be specified in the configuration'));
});

describe('Remote token introspection', () => {
  it('calls fetch with correct parameters for client-based authentication', () => {
    const introspection = new TokenIntrospection({
      endpoint: 'http://example.com/oauth/introspection',
      client_id: 'client',
      client_secret: 'secret',
      async fetch(url, opts) {
        assert.equal(url, 'http://example.com/oauth/introspection');
        assert.equal(opts.method, 'POST');
        assert.equal(opts.headers.Authorization, 'Basic Y2xpZW50OnNlY3JldA==');
        assert.equal(opts.headers['Content-Type'], 'application/x-www-form-urlencoded');
        assert.equal(opts.body, 'token=token&token_type_hint=access_token');
        assert.isNull(opts.agent);
        return {
          ok: true,
          json: () => Promise.resolve({ active: true }),
        };
      },
    });
    return expect(introspection('token', 'access_token')).to.eventually.deep.equal({ active: true });
  });

  it('calls fetch with correct parameters for token-based authentication', () => {
    const introspection = new TokenIntrospection({
      endpoint: 'http://example.com/oauth/introspection',
      access_token: 'test1234',
      async fetch(url, opts) {
        assert.equal(url, 'http://example.com/oauth/introspection');
        assert.equal(opts.method, 'POST');
        assert.equal(opts.headers.Authorization, 'Bearer test1234');
        assert.equal(opts.headers['Content-Type'], 'application/x-www-form-urlencoded');
        assert.equal(opts.body, 'token=token&token_type_hint=access_token');
        assert.isNull(opts.agent);
        return {
          ok: true,
          json: () => Promise.resolve({ active: true }),
        };
      },
    });
    return expect(introspection('token', 'access_token')).to.eventually.deep.equal({ active: true });
  });

  it('calls with special proxy agent if given', () => {
    const introspection = new TokenIntrospection({
      endpoint: 'http://example.com/oauth/introspection',
      client_id: 'client',
      client_secret: 'secret',
      proxy: 'example.proxy.com:3128',
      async fetch(url, opts) {
        assert.typeOf(opts.agent, 'object');
        return {
          ok: true,
          json: () => Promise.resolve({ active: true }),
        };
      },
    });
    return expect(introspection('token', 'access_token')).to.eventually.deep.equal({ active: true });
  });

  it('rejects if token is not active', () => {
    const introspection = new TokenIntrospection({
      endpoint: 'http://example.com/oauth/introspection',
      client_id: 'client',
      client_secret: 'secret',
      async fetch() {
        return {
          ok: true,
          json: () => Promise.resolve({ active: false }),
        };
      },
    });
    return expect(introspection('token', 'access_token')).to.be.rejectedWith(Error, 'Token is not active');
  });
});

describe('Local token introspection with static JWKS', () => {
  it('does local introspection with static keys if JWKS is specified', () => {
    const introspection = new TokenIntrospection({
      fetch: () => {
        throw new Error('should not be called');
      },
      jwks,
    });

    const now = Date.now() / 1000;
    const accessTokenClaims = { exp: now + 5 };
    const accessToken = jwt.sign(accessTokenClaims, privateKey, { algorithm: 'RS256', keyid: keyId, noTimestamp: true });
    return expect(introspection(accessToken, 'access_token')).to.eventually.deep.equal({ active: true, ...accessTokenClaims });
  });

  it('does local introspection with remote keys if JWKS uri is specified', () => {
    const introspection = new TokenIntrospection({
      jwks_uri: jwksUri,
      fetch: () => { throw new Error('should not be called'); },
    });
    nock('http://example.com')
      .get('/jwks')
      .reply(200, JSON.stringify(jwks));

    const now = Date.now() / 1000;
    const accessTokenClaims = { exp: now + 5 };
    const accessToken = jwt.sign(accessTokenClaims, privateKey, { algorithm: 'RS256', keyid: keyId, noTimestamp: true });
    return expect(introspection(accessToken, 'access_token')).to.eventually.deep.equal({ active: true, ...accessTokenClaims });
  });
});

describe('Fallback order for introspection methods: local introspection with static JWKS -> local introspection with remote JWKS -> remote introspection', () => {
  it('falls back to remote introspection if the verification with static JWKS and remote JWKS fails', () => {
    nock('http://example.com')
      .get('/jwks')
      .reply(200, JSON.stringify({ keys: [] })); // no keys

    const introspection = new TokenIntrospection({
      jwks: {}, // no keys
      jwks_uri: jwksUri,
      endpoint: 'http://example.com/oauth/introspection',
      client_id: 'client',
      client_secret: 'secret',
      async fetch() {
        return {
          ok: true,
          json: () => Promise.resolve({ active: true }),
        };
      },
    });
    return expect(introspection('token', 'access_token')).to.eventually.deep.equal({ active: true });
  });
});
