const fetch = require('node-fetch');
const formEncode = require('form-urlencoded');

function tokenIntrospect(opts = {}) {

    const defaults = {
        endpoint: '',
        client_id: '',
        client_secret: '',
        user_agent: 'token-introspection',
        fetch: fetch
    };

    const options = Object.assign({}, defaults, opts);

    if (!options.endpoint) {
        throw new Error('Endpoint is missing from configuration');
    }

    return function introspect(token, tokenTypeHint) {
        data = { token };
        if (tokenTypeHint) {
            data['token_type_hint'] = tokenTypeHint;
        }

        return options.fetch(options.endpoint, {
            method: 'POST',
            body: formEncode(data),
            headers: {
                Authorization: 'Basic ' + new Buffer(`${options.client_id}:${options.client_secret}`).toString('base64'),
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': options.user_agent
            }
        })
        .then(res => res.json())
        .then(data => {
            if (data.active === true) {
                return data;
            } else {
                throw new Error('Token is not active');
            }
        })
        .catch(err => {
            throw err;
        });
    }
}

module.exports = tokenIntrospect;
