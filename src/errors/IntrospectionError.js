module.exports = class IntrospectionError extends Error {
  constructor(message = 'Token introspection failed') {
    super(message);
    this.name = this.constructor.name;
    Error.captureStackTrace(this, this.constructor);
  }
};
