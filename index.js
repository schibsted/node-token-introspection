const formEncode = require('form-urlencoded');

function tokenIntrospect(opts = {}) {
  const defaults = {
    endpoint: '',
    client_id: '',
    client_secret: '',
    user_agent: 'token-introspection',
    proxy: '',
    fetch: null,
  };

  const options = Object.assign({}, defaults, opts);

  if (!options.endpoint) {
    throw new Error('Endpoint is missing from configuration');
  }

  if (!options.fetch) {
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

  return function introspect(token, tokenTypeHint) {
    const data = { token };
    if (tokenTypeHint) {
      data.token_type_hint = tokenTypeHint;
    }

    return options.fetch(options.endpoint, {
      method: 'POST',
      body: formEncode(data),
      headers: {
        Authorization: `Basic ${new Buffer(`${options.client_id}:${options.client_secret}`).toString('base64')}`,
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': options.user_agent,
      },
      agent: proxy,
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
  };
}

module.exports = tokenIntrospect;
