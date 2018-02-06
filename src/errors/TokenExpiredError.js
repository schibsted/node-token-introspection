const TokenNotActiveError = require('./TokenNotActiveError');

module.exports = class TokenExpiredError extends TokenNotActiveError {
  constructor(message = 'Token has expired') {
    super(message);
  }
};
