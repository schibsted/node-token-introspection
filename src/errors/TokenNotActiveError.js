const IntrospectionError = require('./IntrospectionError');

module.exports = class TokenNotActiveError extends IntrospectionError {
  constructor(message) {
    super(message || 'Token is not active');
  }
};
