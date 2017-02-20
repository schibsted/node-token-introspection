# node-token-introspection

Node token introspection package introspects a token towards an oauth service that follows the [RFC 7762](https://tools.ietf.org/html/rfc7662).

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

| Field         | Required | Comment |
| ------------- | :------: | ------- |
| endpoint      | X        | Url to call |
| client_id     |          | Client ID used to introspect |
| client_secret |          | Client secret used to introspect |
