const debug = require('debug')('token-introspection');
const JwksClient = require('jwks-rsa');
const { jwk2pem } = require('pem-jwk');
const jwt = require('jsonwebtoken');
const { promisify } = require('util');
const assert = require('assert');
const errors = require('./errors');

const jwtVerify = promisify(jwt.verify);

module.exports = (options) => {
  let jwksClient = null;
  if (options.jwks && options.jwks.keys) {
    debug('Configured JWKS with static keys');
    const keys = {};
    options.jwks.keys.forEach((k) => {
      keys[k.kid] = jwk2pem(k);
    });
    jwksClient = {
      getSigningKey: async function jwksFetchStaticKey(keyId) {
        assert.ok(keys[keyId], new errors.IntrospectionError('Unable to find key'));
        return { key: keyId, rsaPublicKey: keys[keyId], getPublicKey: () => keys[keyId] };
      },
    };
  } else if (options.jwks_uri) {
    debug('Configured JWKS with remote keys');
    jwksClient = JwksClient({
      cache: options.jwks_cache_enabled || true,
      cacheMaxEntries: options.jwks_cache_maxentries || 10,
      cacheMaxAge: options.jwks_cache_time || 5 * 60 * 1000, // 5 min
      timeout: options.jwks_timeout || 10 * 1000,
      rateLimit: options.jwks_ratelimit_enabled || true,
      jwksRequestsPerMinute: options.jwks_ratelimit_per_minute || 60, // 1 rps
      jwksUri: options.jwks_uri,
      fetcher: options.fetch && (
        (url) => options.fetch(url).then(
          (res) => (res.ok ? res.json() : Promise.reject(new Error(res.statusText))),
        )
      ),
    });
  }

  return async function localIntrospect(token, tokenTypeHint = 'access_token') {
    if (!jwksClient) {
      throw new errors.ConfigurationError('Neither `jwks` or `jwks_uri` defined');
    }

    if (tokenTypeHint !== 'access_token') {
      debug('Not an access token, tokenTypeHint=%s', tokenTypeHint);
      throw new errors.MalformedTokenError('Only access tokens are supported for local introspection');
    }

    const decodedToken = jwt.decode(token, { complete: true });
    if (!decodedToken) {
      debug('Not a JWT token');
      throw new errors.MalformedTokenError('Token is not a JWT');
    }

    if (!decodedToken.header.kid) {
      debug('Tokens does not contain kid in header');
      throw new errors.MalformedTokenError('Token does not contain kid in header');
    }

    let pem;
    try {
      const key = await jwksClient.getSigningKey(decodedToken.header.kid);
      pem = key.getPublicKey();
    } catch (err) {
      throw new errors.MalformedTokenError('Could not find key matching kid');
    }

    try {
      const verified = await jwtVerify(token, pem, { algorithms: options.allowed_algs });
      return { active: true, ...verified };
    } catch (err) {
      if (err instanceof jwt.TokenExpiredError) {
        throw new errors.TokenExpiredError();
      }
      if (err instanceof jwt.NotBeforeError) {
        throw new errors.NotBeforeError();
      }
      throw new errors.IntrospectionError(err.message);
    }
  };
};
