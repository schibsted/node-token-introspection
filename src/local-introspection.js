const debug = require('debug')('token-introspection');
const JwksClient = require('jwks-rsa');
const jwk2pem = require('pem-jwk').jwk2pem;
const jwt = require('jsonwebtoken');
const promisify = require('util.promisify');

const jwtVerify = promisify(jwt.verify);

module.exports = (options) => {
  let jwksFetchKey = null;
  if (options.jwks) {
    debug('Configured JWKS with static keys');
    jwksFetchKey = (key) => {
      const k = options.jwks.keys.find(obj => obj.kid === key);
      if (k) {
        return Promise.resolve(Object.assign({ rsaPublicKey: jwk2pem(k) }, k));
      }
      return Promise.reject('Unable to find key');
    };
  } else if (options.jwks_uri) {
    debug('Configured JWKS with remote keys');
    const jwksClient = new JwksClient({
      cache: options.jwks_cache_enabled || true,
      cacheMaxEntries: options.jwks_cache_maxentries || 10,
      cacheMaxAge: options.jwks_cache_time || 5 * 60 * 1000, // 5 min
      rateLimit: options.jwks_ratelimit_enabled || true,
      jwksRequestsPerMinute: options.jwks_ratelimit_per_minute || 60, // 1 rps
      jwksUri: options.jwks_uri,
    });
    jwksFetchKey = promisify(jwksClient.getSigningKey).bind(jwksClient);
  }

  return async function localIntrospect(token, tokenTypeHint) {
    if (!jwksFetchKey) {
      throw new Error('Neither `jwks` or `jwks_uri` defined');
    }

    if (tokenTypeHint !== 'access_token') {
      debug('Not an access token, tokenTypeHint=%s', tokenTypeHint);
      throw new Error('Only access tokens are supported for local introspection');
    }

    const decodedToken = jwt.decode(token, { complete: true });
    if (!decodedToken) {
      debug('Not a JWT token');
      throw new Error('Token is not a JWT');
    }

    if (!decodedToken.header.kid) {
      debug('Tokens does not contain kid in header');
      throw new Error('Token does not contain kid in header');
    }

    let pem;
    try {
      const key = await jwksFetchKey(decodedToken.header.kid);
      pem = key.publicKey || key.rsaPublicKey;
    } catch (err) {
      throw new Error('Could not find key matching kid');
    }

    try {
      const verified = await jwtVerify(token, pem, { algorithms: options.allowed_algs });
      return Object.assign({ active: true }, verified);
    } catch (err) {
      if (err instanceof jwt.TokenExpiredError) {
        throw new Error('Token has expired');
      }
      throw new Error(`Could not verify token:  ${err.message}`);
    }
  };
};
