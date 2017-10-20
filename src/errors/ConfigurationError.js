const IntrospectionError = require('./IntrospectionError');

module.exports = class ConfigurationError extends IntrospectionError {
  constructor(message) {
    super(message || 'Introspection not properly configured');
  }
};
