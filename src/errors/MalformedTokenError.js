const IntrospectionError = require('./IntrospectionError');

module.exports = class MalformedTokenError extends IntrospectionError {
  constructor(message) {
    super(message || 'Token is malformed');
  }
};
