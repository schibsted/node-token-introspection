const promisify = require('util.promisify');
const debug = require('debug')('token-introspection');
const JwksClient = require('jwks-rsa');
const localIntrospect = require('./local-introspection');
const remoteIntrospect = require('./remote-introspection');

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

  if ((options.jwks_uri || options.endpoint) && !options.fetch) {
    options.fetch = require('node-fetch');
  }

  let proxy = null;
  if (options.proxy) {
    try {
      const HttpsProxy = require('https-proxy-agent');
      proxy = new HttpsProxy(options.proxy);
    } catch (e) {
      throw new Error('Proxy url given, but not installed https-proxy-agent package');
    }
  }

  const remoteIntrospectionInfo = Object.assign({}, options, { proxy });
  let fetchJwks = null;
  if (options.jwks_uri) {
    const client = new JwksClient({
      cache: true,
      rateLimit: true,
      jwksUri: options.jwks_uri,
    });
    fetchJwks = promisify(client.getKeys).bind(client);
  }

  return async function introspect(token, tokenTypeHint) {
    async function tryLocalIntrospect(keys) {
      try {
        return await localIntrospect(keys, options.allowed_algs, token, tokenTypeHint);
      } catch (err) {
        debug('Could not verify token: %s', err.message);
        return null;
      }
    }

    // Verification method order: static JWKS -> remote JWKS -> remote introspection
    let verifiedToken = null;
    if (options.jwks) {
      debug('Using static JWKS to introspect token');
      verifiedToken = await tryLocalIntrospect(options.jwks.keys);
    }

    if (!verifiedToken && fetchJwks) {
      debug('Using remote JWKS to introspect token');
      verifiedToken = await tryLocalIntrospect(await fetchJwks());
    }

    if (verifiedToken) {
      return verifiedToken;
    }

    if (options.endpoint) {
      debug('Doing remote introspection');
      return remoteIntrospect(remoteIntrospectionInfo, token, tokenTypeHint);
    }

    throw new Error('Token is not active');
  };
}

module.exports = tokenIntrospect;
