
require('./_setup')()

var Promise  = require('bluebird')
  , _ = require('lodash')
  , sinon    = require("sinon")
  , createServer = require('../lib/setup')._setupServer
  , authCode = require('../lib/code.js')
  , common   = require('../lib/common.js')
  ;


var tokenEndpoint ='/token'
  , authorizeEndpoint = '/authorize';


syncPromise = function(val, resolve){
    var pro = function(){}   
    pro.then = function(fn, err){
        if ( resolve ) fn(val)
        else  err(val)   
    }
    
}
describe('setup the server as an OAuth2 provider', function(){
   var postToToken, getToAuth, req, res, next, server, options, setup, grants, hooks
     , client = 'the_porch', uri = 'my.example.com', secret = 'secret!'
     , grantStubs;

    beforeEach(function(){
        var _hooks = ['generateUserToken', 'generateRefreshToken', 'exchangeRefreshToken', 'authenticateClient']
        req = { username: 'bob', authorization: {}, body: {}, query: {} }
        res = { header: sinon.spy(), send: sinon.spy(), cache: sinon.spy() }
        next = function(resp){ resp !== null && res.send(resp) }
        server = {
            get:  sinon.spy(function(url, fn){ getToAuth   = _.partial(fn, req, res, next) }),
            post: sinon.spy(function(url, fn){ postToToken = _.partial(fn, req, res, next) }),
            use:  sinon.spy(function(fn){  }) //fn(req, res, next)
        }
    
        grantStubs = getGrantStubs();

        grants = {
            'authorization_code' : grantStubs,
            'client_credentials' : grantStubs,
            'password'           : grantStubs,
            'refresh_token'      : grantStubs,
        }

        hooks = {}
        _.each(_hooks, function(hook){ hooks[hook] = sinon.stub() })
       
        options = {
            grants: ['client_credentials','password','refresh_token'],
            hooks: hooks
        }

        setup = _.partial(createServer, server, options, grants)
    })

    it('should create only one endpoint', function(){
        setup()
        server.post.should.have.been.calledOnce
        server.get.should.not.have.been.called
    })
     
    it('should setup middleware', function(){
        setup()
        server.use.should.have.been.calledOnce
    })

    describe('when authorization_code grant type is selected', function(){
        beforeEach(function(){ 
            options.grants = ['authorization_code', 'refresh_token']
        })

        it('should create both endpoints', function(){
            setup()
            server.post.should.have.been.calledOnce
            server.get.should.have.been.calledOnce
        })
    })

    describe('when posting to the token endpoint', function(){
        beforeEach(function(){
            var base = setup
            setup = function(){ base(); postToToken() } 

            req.method = "POST"
            req.path = function(){ return tokenEndpoint }
            //req.authorization = { scheme: 'basic', basic: { username: client_id, password: secret }}
            req.body = { client_id: client, client_secret: secret, grant_type: 'client_credentials'}
   
            //
        })

        it('should call authenticate hook', function(){
            setup()
            hooks.authenticateClient.should.have.been.calledOnce
            hooks.authenticateClient.should.have.been.calledWith(client, secret)
        })


        describe('when posting with invalid grant type', function(){
            beforeEach(function(){ 
                req.body.grant_type = 'invalid'
            })

            it('should send error', function(){
                setup()
                res.should.have.an.oauthErrorResponse(common.UnsupportedGrantType)
            })
        })


        describe('when client authentication throws an error', function(){
            beforeEach(function(){ 
                hooks.authenticateClient.yields(new Error());
            })

            it('should send error', function(){
                setup()
                res.should.have.an.serverError(Error)
            })
        })

        describe('when client does not authenticate', function(){
            beforeEach(function(){ 
                hooks.authenticateClient.yields(null, false);
            })

            it('should send error', function(){
                setup()
                res.should.have.an.oauthErrorResponse(common.InvalidClientError, 'invalid client')
            })
        })

        describe('when client authenticates', function(){
            var finished, tokens, result;

            beforeEach(function(){ 
                hooks.authenticateClient.yields(null, true);

                grantStubs.validateRequest.returns(Promise.resolve('params'));
                grantStubs.grantToken.returns(Promise.resolve({ token: 'token', refresh: 'refresh' }))

                setup = function(){
                   
                    return new Promise(function(resolve, reject){
                        server.post = sinon.spy(function(url, fn){ 
                            postToToken = _.partial(fn, req, res, reject)
                        })

                        res.send = sinon.spy(resolve)

                        createServer(server, options, grants)
                        postToToken()
                    }) 
                }
            })

            it('should send valid request', function(done){
                setup().then(function(){

                    grantStubs.validateRequest.should.have.been.calledOnce
                    grantStubs.grantToken.should.have.been.calledOnce

                    res.send.should.have.been.calledWithMatch(200, {
                        access_token: 'token',
                        refresh_token: 'refresh',
                        token_type: 'Bearer',
                        expires_in: undefined 
                    })
                })
                .should.notify(done)
            })
        })

    })
    

})



function getGrantStubs(){
    return {
        grantToken: sinon.stub(),
        grantCode: sinon.stub(),
        resourceOwnerApproval: sinon.stub(),
        validateRequest: sinon.stub(),
    }
}