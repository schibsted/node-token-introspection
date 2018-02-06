const debug = require('debug')('token-introspection');
const formEncode = require('form-urlencoded');
const errors = require('./errors');

module.exports = (options) => {
  const fetchOption = {
    method: 'POST',
    headers: {
      Authorization: `Basic ${Buffer.from(`${options.client_id}:${options.client_secret}`).toString('base64')}`,
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': options.user_agent,
    },
    agent: options.proxy,
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
        Object.assign({ body: formEncode(data) }, fetchOption),
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
    if (tokenData.active === true) {
      return tokenData;
    }

    throw new errors.TokenNotActiveError();
  };
};
