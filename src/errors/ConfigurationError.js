const IntrospectionError = require('./IntrospectionError');

module.exports = class ConfigurationError extends IntrospectionError {
  constructor(message = 'Introspection not properly configured') {
    super(message);
  }
};
