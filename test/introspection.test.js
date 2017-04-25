const assert = require('chai').assert;
const expect = require('chai').expect;
const chai = require('chai');
const chaiAsPromised = require('chai-as-promised');
const TokenIntrospection = require('../index');

chai.use(chaiAsPromised);

describe('Token introspection', () => {
    it('throws error if endpoint is missing', () => {
        expect(() => { new TokenIntrospection() }).to.throw(Error);
    });

    it('calls fetch with correct parameters', () => {
        const introspection = new TokenIntrospection({
            endpoint: 'http://example.com/oauth/introspection',
            client_id: 'client',
            client_secret: 'secret',
            fetch: (url, opts) => {
                assert.equal(url, 'http://example.com/oauth/introspection');
                assert.equal(opts.method, 'POST');
                assert.equal(opts.headers.Authorization, 'Basic Y2xpZW50OnNlY3JldA==');
                assert.equal(opts.headers['Content-Type'], 'application/x-www-form-urlencoded');
                assert.equal(opts.body, 'token=token&token_type_hint=access_token');
                assert.isNull(opts.agent);
                return Promise.resolve({ json: () => ({active: true}) });
            }
        });
        expect(introspection('token', 'access_token')).to.eventually.have.property('active');
        expect(introspection('token', 'access_token')).to.eventually.deep.equal({active: true});
    });

    it('calls with special proxy agent if given', () => {
        const introspection = new TokenIntrospection({
            endpoint: 'http://example.com/oauth/introspection',
            client_id: 'client',
            client_secret: 'secret',
            proxy: 'example.proxy.com:3128',
            fetch: (url, opts) => {
                assert.typeOf(opts.agent, 'object');
                return Promise.resolve({ json: () => ({active: true}) });
            }
        });
        expect(introspection('token', 'access_token')).to.eventually.have.property('active');
    });

    it('rejects if token is not active', () => {
        const introspection = new TokenIntrospection({
            endpoint: 'http://example.com/oauth/introspection',
            client_id: 'client',
            client_secret: 'secret',
            fetch: (url, opts) => {
                return Promise.resolve({ json: () => ({active: false}) });
            }
        });
        expect(introspection('token', 'access_token')).to.be.rejectedWith(Error);
    });
});
