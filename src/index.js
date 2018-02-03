const debug = require('debug')('token-introspection');
const localIntrospection = require('./local-introspection');
const remoteIntrospection = require('./remote-introspection');
const errors = require('./errors');

function tokenIntrospect(opts = {}) {
  const defaults = {
    jwks: null,
    jwks_uri: '',
    endpoint: '',
    allowed_algs: ['RS256'],
    client_id: '',
    client_secret: '',
    user_agent: 'token-introspection',
    proxy: '',
    fetch: null,
  };

  const options = Object.assign({}, defaults, opts);

  if (!options.jwks && !options.jwks_uri && !options.endpoint) {
    throw new errors.ConfigurationError('Static JWKS, a JWKS URI or introspection endpoint must be specified in the configuration');
  }

  if ((options.jwks_uri || options.endpoint) && !options.fetch) {
    options.fetch = require('node-fetch');
  }

  let proxy = null;
  if (options.proxy) {
    try {
      const HttpsProxy = require('https-proxy-agent');
      proxy = new HttpsProxy(options.proxy);
      process.env.HTTPS_PROXY = options.proxy;
    } catch (e) {
      throw new errors.ConfigurationError('Proxy given, but missing https-proxy-agent package');
    }
  }

  const remoteIntrospect = remoteIntrospection(Object.assign({}, options, { proxy }));
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
module.exports.errors = errors;
