const fetch = require('node-fetch');
const FormData = require('form-data');

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
        const form = new FormData();
        form.append('token', token);
        if (tokenTypeHint) {
            form.append('token_type_hint', tokenTypeHint);
        }

        return options.fetch(options.endpoint, {
            method: 'POST',
            body: form,
            headers: {
                Authorization: 'Basic ' + new Buffer(`${options.client_id}:${options.client_secret}`).toString('base64'),
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
