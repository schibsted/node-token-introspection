const expect = require('chai').expect;
const chai = require('chai');
const chaiAsPromised = require('chai-as-promised');
const localIntrospection = require('../lib/local-introspection');
const errors = require('../lib/errors');

const fs = require('fs');
const jwt = require('jsonwebtoken');
const pem2jwk = require('pem-jwk').pem2jwk;

chai.use(chaiAsPromised);

const keyId = 'test_key_id';
function setupPublicKeyJWK() {
  const publicKey = fs.readFileSync('./test/public.pem', 'ascii');
  const jwk = pem2jwk(publicKey);
  return Object.assign({ kid: keyId, use: 'sig' }, jwk);
}
function jwksWrap(keys) {
  return { keys };
}
const privateKey = fs.readFileSync('./test/private.pem', 'ascii');
const publicKeyJWK = setupPublicKeyJWK();

describe('Local token introspection', () => {
  it('verifies a token signed with a known key', () => {
    const now = Date.now() / 1000;
    const accessTokenClaims = { exp: now + 5 };
    const accessToken = jwt.sign(accessTokenClaims, privateKey, { algorithm: 'RS256', keyid: keyId, noTimestamp: true });
    const localIntrospect = localIntrospection({ jwks: jwksWrap([publicKeyJWK]), allowed_algs: ['RS256'] });
    return expect(localIntrospect(accessToken, 'access_token')).to.eventually.deep.equal(Object.assign({ active: true }, accessTokenClaims));
  });

  it('rejects mismatching kid for static JWKS', () => {
    const now = Date.now() / 1000;
    const accessTokenClaims = { exp: now + 5 };
    const accessToken = jwt.sign(accessTokenClaims, privateKey, { algorithm: 'RS256', keyid: 'other_key_id' });
    const localIntrospect = localIntrospection({ jwks: jwksWrap([publicKeyJWK]), allowed_algs: ['RS256'] });
    return expect(localIntrospect(accessToken, 'access_token')).to.be.rejectedWith(Error, 'Could not find key matching kid');
  });

  it('rejects other token type than access_token', () => {
    const localIntrospect = localIntrospection({ jwks: jwksWrap([publicKeyJWK]), allowed_algs: ['RS256'] });
    return expect(localIntrospect('foobar', 'other_token')).to.be.rejectedWith(Error, 'Only access tokens are supported for local introspection');
  });

  it('rejects expired token', () => {
    const before = (Date.now() / 1000) - 1000;
    const accessTokenClaims = { iat: before, exp: before + 5 };
    const accessToken = jwt.sign(accessTokenClaims, privateKey, { algorithm: 'RS256', keyid: keyId });
    const localIntrospect = localIntrospection({ jwks: jwksWrap([publicKeyJWK]), allowed_algs: ['RS256'] });
    return expect(localIntrospect(accessToken, 'access_token')).to.be.rejectedWith(errors.TokenExpiredError, 'Token has expired');
  });

  it('rejects non-jwt token', () => {
    const localIntrospect = localIntrospection({ jwks: jwksWrap([publicKeyJWK]), allowed_algs: ['RS256'] });
    return expect(localIntrospect('foobar', 'access_token')).to.be.rejectedWith(Error, 'Token is not a JWT');
  });

  it('rejects symmetrically signed token', () => {
    const now = Date.now() / 1000;
    const accessTokenClaims = { exp: now + 5 };
    const secretKey = 'super secret key';
    const accessToken = jwt.sign(accessTokenClaims, secretKey, { algorithm: 'HS256' });
    const localIntrospect = localIntrospection({ jwks: jwksWrap([publicKeyJWK]), allowed_algs: ['RS256'] });
    return expect(localIntrospect(accessToken, 'access_token')).to.be.rejectedWith(Error, 'Token does not contain kid in header');
  });
});
