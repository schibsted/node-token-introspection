const IntrospectionError = require('./IntrospectionError');

module.exports = class MalformedTokenError extends IntrospectionError {
  constructor(message = 'Token is malformed') {
    super(message);
  }
};
