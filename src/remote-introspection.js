const debug = require('debug')('token-introspection');
const formEncode = require('form-urlencoded');

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

module.exports = remoteIntrospect;
