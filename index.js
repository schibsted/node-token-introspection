const formEncode = require('form-urlencoded');
const promisify = require('util.promisify');
const debug = require('debug')('token-introspection');
const JwksClient = require('jwks-rsa');
const jwt = require('jsonwebtoken');
const jwk2pem = require('pem-jwk').jwk2pem;

const jwtVerify = promisify(jwt.verify);

async function localIntrospect(keys, allowedAlgorithms, token, tokenTypeHint) {
  function findCandidateKeys(jwtHeader) {
    function alg2keyType(alg) {
      if (alg.startsWith('HS')) {
        return 'oct';
      } else if (alg.startsWith('RS') || alg.startsWith('PS')) {
        return 'RSA';
      } else if (alg.startsWith('ES')) {
        return 'EC';
      }
      return null;
    }

    const filteredKeys = keys.slice()
      .filter(key => key.kty && key.kty === alg2keyType(jwtHeader.alg));
    debug('Filtered keys for \'%s\', found %d', jwtHeader.alg, filteredKeys.length);

    if (jwtHeader.kid) {
      const keyWithKeyId = filteredKeys.find(key => key.kid === jwtHeader.kid);
      if (keyWithKeyId) {
        debug('Found key for key id %s', jwtHeader.kid);
        return [keyWithKeyId];
      }
      debug('No key found for key id %s', jwtHeader.kid);
      return [];
    }

    return filteredKeys;
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

  const possibleVerificationKeys = findCandidateKeys(decodedToken.header)
    .map(jwk2pem);

  /* eslint-disable no-restricted-syntax, no-await-in-loop */
  for (const key of possibleVerificationKeys) {
    try {
      const verified = await jwtVerify(token, key, { algorithms: allowedAlgorithms });
      return Object.assign({ active: true }, verified);
    } catch (err) {
      if (err instanceof jwt.TokenExpiredError) {
        throw new Error('Token has expired');
      }
    }
  }
  /* eslint-enable */

  throw new Error('Could not verify token with any key');
}

function remoteIntrospect(requestInfo, token, tokenTypeHint) {
  const data = { token };
  if (tokenTypeHint) {
    data.token_type_hint = tokenTypeHint;
  }

  return requestInfo.fetch(requestInfo.endpoint, {
    method: 'POST',
    body: formEncode(data),
    headers: {
      Authorization: `Basic ${new Buffer(`${requestInfo.client_id}:${requestInfo.client_secret}`).toString('base64')}`,
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': requestInfo.user_agent,
    },
    agent: requestInfo.proxy,
  })
    .then(res => res.json())
    .then((tokenData) => {
      if (tokenData.active === true) {
        return tokenData;
      }
      throw new Error('Token is not active');
    })
    .catch((err) => {
      throw err;
    });
}

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

  if (options.jwks_uri && !options.fetch) {
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
