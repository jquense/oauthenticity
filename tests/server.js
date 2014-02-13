
require('./_setup')()

var Promise  = require('bluebird')
  , _ = require('lodash')
  , sinon    = require("sinon")
  , oauth = require('../lib/setup')
  , createServer = oauth._setupServer
  , authCode = require('../lib/code.js')
  , errors   = require('../lib/errors.js')
  ;

var tokenEndpoint ='/token'
  , authorizeEndpoint = '/authorize';



describe('setup the server as an OAuth2 provider', function(){
   var postToToken, getToAuth, req, res, next, server, options, setup, grants, hooks
     , sendJson, sendError
     , client = 'the_porch', uri = 'my.example.com', secret = 'secret!'
     , grantStubs;

    beforeEach(function(){
        var _hooks = ['generateUserToken', 'generateRefreshToken', 'exchangeRefreshToken', 'authenticateClient']
        req = { username: 'bob', authorization: {}, body: {}, query: {} }
        res = { writeHead: sinon.spy(), setHeader: sinon.spy(), end: sinon.spy(), cache: sinon.spy() }
        
        sendJson  = oauth._sendJson = sinon.spy()
        sendError = oauth._respondWithError = sinon.spy()

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
                sendError.should.have.an.oauthErrorResponse(errors.UnsupportedGrantType)
            })
        })

        describe('when client authentication throws an error', function(){
            beforeEach(function(){ 
                hooks.authenticateClient.yields(new Error());
            })

            it('should send error', function(){
                setup()
                sendError.should.have.an.serverError(Error)
            })
        })

        describe('when client does not authenticate', function(){
            beforeEach(function(){ 
                hooks.authenticateClient.yields(null, false);
            })

            it('should send error', function(){
                setup()
                sendError.should.have.an.oauthErrorResponse(errors.InvalidClientError, 'invalid client')
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

                        sendJson = oauth._sendJson = sinon.spy(resolve)

                        createServer(server, options, grants)
                        postToToken()
                    }) 
                }
            })

            it('should send valid request', function(done){
                setup().then(function(){

                    grantStubs.validateRequest.should.have.been.calledOnce
                    grantStubs.grantToken.should.have.been.calledOnce

                    sendJson.should.have.been.calledWithMatch(200, {
                        access_token: 'token',
                        refresh_token: 'refresh',
                        token_type: 'Bearer',
                        expires_in: undefined 
                    }, res)
                })
                .should.notify(done)
            })
        })

    })
    
    describe('when GET to the authorization endpoint', function(){
        beforeEach(function(){
            var base = setup

            //setup = function(){ base(); getToAuth() } 
            req.query = {}
            req.method = "GET"
            req.path = function(){ return authorizeEndpoint }
            
            options.grants = ['authorization_code', 'refresh_token']

            setup = function(client_id, redirect_uri, response_type){
                base()
                getToAuth()
            }
        })
        

        describe('when a request is missing client_id', function(){
             beforeEach(function(){
                req.query = { redirect_uri: uri, response_type: 'code'}    
            })
            it('should send an error', function(){
                setup()
                sendError.should.be.an.oauthErrorResponse(errors.InvalidRequestError, 'client_id')
            });
        });

        describe('when a request as missing redirect_uri', function(){
            beforeEach(function(){
                req.query = { response_type: 'code', client_id: client}    
            })

            it('should send an error', function(){
                setup()
                sendError.should.be.an.oauthErrorResponse(errors.InvalidRequestError, 'redirect_uri')
            });
        });

        describe('when a request is missing response_type', function(){
            beforeEach(function(){
                req.query = { redirect_uri: uri, client_id: client}    
            })
            it('should send an error', function(){
                setup()
                sendError.should.be.an.oauthErrorResponse(errors.InvalidRequestError, 'response_type')
            });
        });
   
        describe('when a request redirect_uri contains a hash fragment', function(){
            beforeEach(function(){
                req.query = { response_type: 'code', client_id: client, redirect_uri: 'https://c.c.com?hello#dfdsf' }    
            })

            it('should send an error', function(){
                setup()
                sendError.should.be.an.oauthErrorResponse(errors.InvalidRequestError, 
                    'redirect_uri cannot contain a hash (#) fragment.')
            });
        });

        describe('when a request response_type is invalid', function(){
            beforeEach(function(){
                req.query = { response_type: 'boooom', client_id: client, redirect_uri: uri }    
            })

            it('should send an error', function(){
                setup()
                sendError.should.be.an.oauthErrorResponse(errors.InvalidRequestError, 
                    'the response_type must either be \'token\' or \'code\'')
            });

        });

        describe('when the request validates', function(){
            beforeEach(function(){ 
                var baseSetup = setup

                setup = function(cb){
                    res.end = sinon.spy(cb)
                    sendError = oauth._respondWithError = sinon.spy(cb)
                    baseSetup()
                }

                req.query = { client_id: client, redirect_uri: uri, response_type: 'code'}
                grantStubs.grantCode.returns(Promise.resolve('a_code'));
                grantStubs.resourceOwnerApproval.returns(Promise.resolve(true));
                
            })    
            
            it('hand call for authentication correctly', function(done){
                setup(function(err){
                    grantStubs.resourceOwnerApproval.should.be.calledWith(req, res, client, uri)
                    done()
                })
            });

            it('should redirect with a code', function(done){
                setup(function(err){
                    grantStubs.resourceOwnerApproval.should.be.calledWith(req, res, client, uri)

                    res.writeHead.should.be.an.calledWithMatch(302, { 'Location': uri + '?code=a_code' })
                    done()
                })
            });
            describe('when the response_type is \'token\'', function(){
            
                beforeEach(function(){ 
                    req.query.response_type = 'token'
                }) 

                it('should redirect with a token in the fragment', function(done){
                    setup(function(err){
                        grantStubs.resourceOwnerApproval.should.be.calledWith(req, res, client, uri)

                        res.writeHead.should.be.an.calledWithMatch(302, 
                            { 'Location': uri + '#access_token=a_code&token_type=bearer' })
                        done()
                    })
                });

            });

            describe('when the user denies access', function(){
            
                beforeEach(function(){ 
                    req.query = { client_id: client, redirect_uri: uri, response_type: 'code'}
                    grantStubs.resourceOwnerApproval.returns(Promise.reject(new errors.AccessDeniedError('no dice')));
                })    
            
                it('should halt the process and error out', function(done){
                    setup(function(err){
                        grantStubs.resourceOwnerApproval.should.be.calledWith(req, res, client, uri)
                        grantStubs.grantCode.should.not.have.been.called

                        sendError.should.be.an.oauthErrorResponse(errors.AccessDeniedError, 'no dice')
                        done()
                    })
                });
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