const TokenNotActiveError = require('./TokenNotActiveError');

module.exports = class NotBeforeError extends TokenNotActiveError {
  constructor(message) {
    super(message || 'Token is not yet valid');
  }
};
