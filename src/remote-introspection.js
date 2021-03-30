const debug = require('debug')('token-introspection');
const formEncode = require('form-urlencoded').default;
const errors = require('./errors');

module.exports = (options) => {
  const authorization = options.access_token
    ? `Bearer ${options.access_token}`
    : `Basic ${Buffer.from(`${options.client_id}:${options.client_secret}`).toString('base64')}`;

  const fetchOption = {
    method: 'POST',
    headers: {
      Authorization: authorization,
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': options.user_agent,
    },
  };

  return async function remoteIntrospect(token, tokenTypeHint) {
    const data = { token };
    if (tokenTypeHint) {
      data.token_type_hint = tokenTypeHint;
    }
    let res;
    try {
      res = await options.fetch(
        options.endpoint,
        { body: formEncode(data), ...fetchOption },
      );
    } catch (err) {
      debug(`Remote token introspection request failed: ${err.message}`);
      throw new errors.IntrospectionError('Remote introspection request failed');
    }

    if (!res.ok) {
      const errorBody = await res.text();
      throw new errors.IntrospectionError(`Server error ${res.status} ${res.statusText} ${res.url} \n${errorBody}`);
    }

    const tokenData = await res.json();
    if (tokenData.active === true || tokenData.active === 'true') {
      return tokenData;
    }

    throw new errors.TokenNotActiveError();
  };
};
