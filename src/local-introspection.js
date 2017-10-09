const debug = require('debug')('token-introspection');
const jwk2pem = require('pem-jwk').jwk2pem;
const jwt = require('jsonwebtoken');
const promisify = require('util.promisify');

const jwtVerify = promisify(jwt.verify);

async function localIntrospect(keys, allowedAlgorithms, token, tokenTypeHint) {
  if (tokenTypeHint !== 'access_token') {
    debug('Not an access token, tokenTypeHint=%s', tokenTypeHint);
    throw new Error('Only access tokens are supported for local introspection');
  }

  const decodedToken = jwt.decode(token, { complete: true });
  if (!decodedToken) {
    debug('Not a JWT token');
    throw new Error('Token is not a JWT');
  }

  const possibleVerificationKeys = findCandidateKeys(decodedToken.header, keys)
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

function findCandidateKeys(jwtHeader, keys) {
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

module.exports = localIntrospect;
