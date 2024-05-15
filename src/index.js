const debug = require('debug')('token-introspection');
const jwt = require('jsonwebtoken');
const localIntrospection = require('./local-introspection');
const remoteIntrospection = require('./remote-introspection');
const errors = require('./errors');

function tokenIntrospect(opts = {}) {
  const defaults = {
    jwks: null,
    jwks_uri: '',
    jwks_client_fetcher: null,
    endpoint: '',
    allowed_algs: ['RS256'],
    client_id: '',
    client_secret: '',
    user_agent: 'token-introspection',
    fetch: null,
  };

  const options = { ...defaults, ...opts };

  if (!options.jwks && !options.jwks_uri && !options.endpoint) {
    throw new errors.ConfigurationError('Static JWKS, a JWKS URI or introspection endpoint must be specified in the configuration');
  }

  if ((options.jwks_uri || options.endpoint) && !options.fetch) {
    options.fetch = require('node-fetch').default;
  }

  const remoteIntrospect = remoteIntrospection(options);
  const localIntrospect = localIntrospection(options);

  return async function introspect(token, tokenTypeHint) {
    try {
      return await localIntrospect(token, tokenTypeHint);
    } catch (err) {
      debug(`Could not locally verify token: ${err.message}`);
      if (err instanceof errors.TokenExpiredError || err instanceof errors.NotBeforeError) {
        throw err;
      }
    }

    if (options.endpoint) {
      debug('Doing remote introspection');
      return remoteIntrospect(token, tokenTypeHint);
    }

    throw new errors.TokenNotActiveError();
  };
}

module.exports = tokenIntrospect;
module.exports.peek = (token) => jwt.decode(token, { complete: true });
module.exports.errors = errors;
