const assert = require('chai').assert;
const expect = require('chai').expect;
const chai = require('chai');
const chaiAsPromised = require('chai-as-promised');
const nock = require('nock');
const TokenIntrospection = require('../index');

const fs = require('fs');
const jwt = require('jsonwebtoken');
const pem2jwk = require('pem-jwk').pem2jwk;

chai.use(chaiAsPromised);
nock.disableNetConnect();

const keyId = 'test_key_id';
function setupJwks() {
  const publicKey = fs.readFileSync('./test/public.pem', 'ascii');
  const jwk = pem2jwk(publicKey);
  return { keys: [Object.assign({ kid: keyId }, jwk)] };
}
const privateKey = fs.readFileSync('./test/private.pem', 'ascii');
const jwks = setupJwks(keyId);
const jwksUri = 'http://example.com/jwks';

describe('Configuration', () => {
  it('throws error if required config is missing', () => expect(() => TokenIntrospection()).to.throw(Error, 'must be specified in the configuration'));
});

describe('Remote token introspection', () => {
  it('calls fetch with correct parameters', () => {
    const introspection = new TokenIntrospection({
      endpoint: 'http://example.com/oauth/introspection',
      client_id: 'client',
      client_secret: 'secret',
      fetch: (url, opts) => {
        assert.equal(url, 'http://example.com/oauth/introspection');
        assert.equal(opts.method, 'POST');
        assert.equal(opts.headers.Authorization, 'Basic Y2xpZW50OnNlY3JldA==');
        assert.equal(opts.headers['Content-Type'], 'application/x-www-form-urlencoded');
        assert.equal(opts.body, 'token=token&token_type_hint=access_token');
        assert.isNull(opts.agent);
        return Promise.resolve({ json: () => ({ active: true }) });
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
      fetch: (url, opts) => {
        assert.typeOf(opts.agent, 'object');
        return Promise.resolve({ json: () => ({ active: true }) });
      },
    });
    return expect(introspection('token', 'access_token')).to.eventually.deep.equal({ active: true });
  });

  it('rejects if token is not active', () => {
    const introspection = new TokenIntrospection({
      endpoint: 'http://example.com/oauth/introspection',
      client_id: 'client',
      client_secret: 'secret',
      fetch: () => Promise.resolve({ json: () => ({ active: false }) }),
    });
    return expect(introspection('token', 'access_token')).to.be.rejectedWith(Error, 'Token is not active');
  });
});

describe('Local token introspection with static JWKS', () => {
  const introspection = new TokenIntrospection({
    fetch: () => {
      throw new Error('should not be called');
    },
    jwks,
  });

  it('does local introspection if JWKS is specified', () => {
    const now = Date.now() / 1000;
    const accessTokenClaims = { exp: now + 5 };
    const accessToken = jwt.sign(accessTokenClaims, privateKey, { algorithm: 'RS256', keyid: keyId, noTimestamp: true });
    return expect(introspection(accessToken, 'access_token')).to.eventually.deep.equal(Object.assign({ active: true }, accessTokenClaims));
  });

  it('finds matching key for token without kid', () => {
    const keys = jwks.keys.slice();
    const otherKey = { n: '5hkbMTpub6WuqITpPhQHr5nvYz1t7PUg8ph9DEi55TtJXUT46S6viY-lNpBdLCOWes3mDD0VWKyXMO9JAeB9nw', e: 'AQAB' };
    keys.unshift(otherKey);
    const instance = new TokenIntrospection({
      fetch: () => {
        throw new Error('should not be called');
      },
      jwks: { keys },
    });

    const now = Date.now() / 1000;
    const accessTokenClaims = { exp: now + 5 };
    const accessToken = jwt.sign(accessTokenClaims, privateKey, { algorithm: 'RS256', noTimestamp: true });
    return expect(instance(accessToken, 'access_token')).to.eventually.deep.equal(Object.assign({ active: true }, accessTokenClaims));
  });

  it('rejects mismatching kid for static JWKS', () => {
    const now = Date.now() / 1000;
    const accessTokenClaims = { exp: now + 5 };
    const accessToken = jwt.sign(accessTokenClaims, privateKey, { algorithm: 'RS256', keyid: 'other_key_id' });
    return expect(introspection(accessToken, 'access_token')).to.be.rejectedWith(Error, 'Token is not active');
  });

  it('rejects other token type than access_token', () => expect(introspection('foobar', 'other_token')).to.be.rejectedWith(Error, 'Token is not active'));

  it('rejects expired token', () => {
    const before = (Date.now() / 1000) - 1000;
    const accessTokenClaims = { iat: before, exp: before + 5 };
    const accessToken = jwt.sign(accessTokenClaims, privateKey, { algorithm: 'RS256' });
    return expect(introspection(accessToken, 'access_token')).to.be.rejectedWith(Error, 'Token is not active');
  });

  it('rejects non-jwt token', () => expect(introspection('foobar', 'access_token')).to.be.rejectedWith(Error, 'Token is not active'));
});

describe('Local token introspection with remote JWKS', () => {
  const introspection = new TokenIntrospection({
    jwks_uri: jwksUri,
    fetch: () => { throw new Error('should not be called'); },
  });

  it('does local introspection if JWKS uri is specified', () => {
    nock('http://example.com')
      .get('/jwks')
      .reply(200, JSON.stringify(jwks));
    const now = Date.now() / 1000;
    const accessTokenClaims = { exp: now + 5 };
    const accessToken = jwt.sign(accessTokenClaims, privateKey, { algorithm: 'RS256', keyid: keyId, noTimestamp: true });
    return expect(introspection(accessToken, 'access_token')).to.eventually.deep.equal(Object.assign({ active: true }, accessTokenClaims));
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
      fetch: () => Promise.resolve({ json: () => ({ active: true }) }),
    });
    return expect(introspection('token', 'access_token')).to.eventually.deep.equal({ active: true });
  });
});
