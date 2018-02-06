const IntrospectionError = require('./IntrospectionError');

module.exports = class TokenNotActiveError extends IntrospectionError {
  constructor(message = 'Token is not active') {
    super(message);
  }
};
