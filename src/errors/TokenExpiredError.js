const TokenNotActiveError = require('./TokenNotActiveError');

module.exports = class TokenExpiredError extends TokenNotActiveError {
  constructor(message) {
    super(message || 'Token has expired');
  }
};
