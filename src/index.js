const debug = require('debug')('token-introspection');
const localIntrospection = require('./local-introspection');
const remoteIntrospection = require('./remote-introspection');

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
    throw new Error('Static JWKS, a JWKS URI or introspection endpoint must be specified in the configuration');
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
      throw new Error('Proxy url given, but not installed https-proxy-agent package');
    }
  }

  const remoteIntrospect = remoteIntrospection(Object.assign({}, options, { proxy }));
  const localIntrospect = localIntrospection(options);

  return async function introspect(token, tokenTypeHint) {
    try {
      return await localIntrospect(token, tokenTypeHint);
    } catch (err) {
      debug('Could not verify token: %s', err.message);
    }

    if (options.endpoint) {
      debug('Doing remote introspection');
      return remoteIntrospect(token, tokenTypeHint);
    }

    throw new Error('Token is not active');
  };
}

module.exports = tokenIntrospect;
