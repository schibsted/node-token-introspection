const request = require('request-promise');

function tokenIntrospect(opts) {

    const defaults = {
        endpoint: '',
        client_id: '',
        client_secret: ''
    };

    const options = Object.assign({}, defaults, opts);

    if (!options.endpoint) {
        throw new Error('Endpoint is missing from configuration');
    }

    return function introspect(token, tokenTypeHint) {
        const form = { token: token };
        if (tokenTypeHint) {
            form.token_type_hint = tokenTypeHint;
        }
        return request({
            method: 'POST',
            url: options.endpoint,
            form: form,
            json: true,
            headers: {
                Authorization: 'Basic ' + new Buffer(`${options.client_id}:${options.client_secret}`).toString('base64'),
                'User-Agent': 'admin-service'
            }
        })
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
