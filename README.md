# node-token-introspection

Node token introspection package introspects a token towards an oauth service that follows the [RFC 7662](https://tools.ietf.org/html/rfc7662).

## Install

```bash
npm install token-introspection --save
```

## Usage

Introspect package is configured with endpoint and client credentials, and a function is returned.
Calling that function with token, and optional token_type_hint will return a
[Promise](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise).

```javascript
const tokenIntrospection = require('token-introspection')({
    endpoint: 'https://example.com/introspect',
    client_id: '<Client ID>',
    client_secret: '<Client Secret>',
});

tokenIntrospection(token).then(console.log).catch(console.warn);
```

## Configuration

| Field                     | Required | Comment |
| ------------------------- | :------: | ------- |
| jwks                      | (X)      | Static JWKS of trusted keys, for example `{keys: [{kty:'RSA',n:'4-4mhUVhY2k',e:'AQAB'}]}` |
| jwks_uri                  | (X)      | URL of a trusted JWKS, for example `https://example.com/jwks` |
| endpoint                  | (X)      | URL to call, for instance https://example.com/introspect |
| allowed_algs              |          | List of allowed signing algorithms, defaults to `['RS256']` |
| jwks_cache_enabled        |          | If jwks response should be cached, defaults to true |
| jwks_cache_maxentries     |          | How many jwk's to cache, defaults to 10 |
| jwks_cache_time           |          | How long a jwk is cached, in ms, defaults to 5 min |
| jwks_ratelimit_enabled    |          | If ratelimit of calls to jwks endpoint, defaults to true |
| jwks_ratelimit_per_minute |          | Limits of jwks calls, defaults to 60 rpm |
| client_id                 |          | Client ID used to introspect |
| client_secret             |          | Client secret used to introspect |
| user_agent                |          | Defaults to `token-introspection` |
| proxy                     |          | Optional url with port to proxy request through. Requires optional dependency [https-proxy-agent](https://www.npmjs.com/package/https-proxy-agent) |
| fetch                     |          | Defaults to [node-fetch](https://github.com/bitinn/node-fetch), but you can inject [zipkin-instrumentation-fetch](https://www.npmjs.com/package/zipkin-instrumentation-fetch). |

At least one of the required configuration parameters `jwks`, `jwks_uri` or `endpoint` must be specified.

## Showing debug output

Set the environment variable `DEBUG=token-introspection`.
