const debug = require('debug')('token-introspection');
const formEncode = require('form-urlencoded');

async function remoteIntrospect(requestInfo, token, tokenTypeHint) {
  const data = { token };
  if (tokenTypeHint) {
    data.token_type_hint = tokenTypeHint;
  }
  
  let res;
  try {
    res = await requestInfo.fetch(requestInfo.endpoint, {
      method: 'POST',
      body: formEncode(data),
      headers: {
        Authorization: `Basic ${new Buffer(`${requestInfo.client_id}:${requestInfo.client_secret}`).toString('base64')}`,
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': requestInfo.user_agent,
      },
      agent: requestInfo.proxy,
    });
  } catch (err) {
    debug('Remote token introspection request failed: ' + err.message);
    throw new Error('Remote introspection request failed');
  }

  const tokenData = res.json();
  if (tokenData.active === true) {
    return tokenData;
  }
  throw new Error('Token is not active');
}

module.exports = remoteIntrospect;
