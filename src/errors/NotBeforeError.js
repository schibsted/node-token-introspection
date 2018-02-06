const TokenNotActiveError = require('./TokenNotActiveError');

module.exports = class NotBeforeError extends TokenNotActiveError {
  constructor(message = 'Token is not yet valid') {
    super(message);
  }
};
