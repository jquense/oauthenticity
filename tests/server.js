
require('./_setup')()

var Promise  = require('bluebird')
  , _ = require('lodash')
  , format = require('util').format
  , sinon    = require("sinon")
  , oauth = require('../lib/setup')
  , createServer = oauth._setupServer
  , authCode = require('../lib/code.js')
  , errors   = require('../lib/errors.js')
  ;

var tokenEndpoint ='/token'
  , authorizeEndpoint = '/authorize';



describe('setup the server as an OAuth2 provider', function(){
   var postToToken, getToAuth, middleware, req, res, next, server, options, setup, grants, hooks
     , sendJson, sendError
     , client = 'the_porch', uri = 'my.example.com', secret = 'secret!'
     , grantStubs;

    beforeEach(function(){
        var _hooks = ['validateToken', 'generateUserToken', 'generateRefreshToken', 'exchangeRefreshToken', 'authenticateClient']
        req = { username: 'bob', authorization: {}, body: {}, query: {}, url: 'a/route/' }
        res = { writeHead: sinon.spy(), setHeader: sinon.spy(), end: sinon.spy(), cache: sinon.spy() }
        
        sendJson  = oauth._sendJson = sinon.spy()
        sendError = oauth._respondWithError = sinon.spy()

        next = sinon.spy(function(resp){ resp !== null && sendError(resp) })

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
            tokenEndpoint: tokenEndpoint,
            authorizeEndpoint: authorizeEndpoint,
            hooks: hooks
        }

        setup = function(){
            var routes = createServer( options, grants);
            middleware  = _.partial(routes.middleware, req, res, next);
            postToToken = _.partial(routes.tokenEndpoint, req, res, next);

            if (routes.authorizationEndpoint )
                getToAuth = _.partial(routes.authorizationEndpoint, req, res, next);

            return routes;
        }
    })

    it('should create only one endpoint', function(){
        var routes = setup()

        routes.should.have.property('tokenEndpoint')
        routes.should.not.have.property('authorizationEndpoint')
    })
     
    it('should setup middleware', function(){
        var routes = setup()
        routes.should.have.property('middleware')
    })

    describe('when authorization_code grant type is selected', function(){
        beforeEach(function(){ 
            options.grants = ['authorization_code', 'refresh_token']
        })

        it('should create both endpoints', function(){
            var routes = setup()

            routes.should.have.property('tokenEndpoint')
            routes.should.have.property('authorizationEndpoint')
        })
    })

    describe('when posting to the token endpoint', function(){
        beforeEach(function(){
            var base = setup
            setup = function(){ base(); postToToken() } 

            req.method = "POST"
            req.url = tokenEndpoint
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
                        var routes = createServer( options, grants)

                        postToToken = _.partial(routes.tokenEndpoint, req, res, reject)
                        sendJson = oauth._sendJson = sinon.spy(resolve)

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
            req.url = authorizeEndpoint
            
            options.grants = ['authorization_code', 'refresh_token']

            setup = function(client_id, redirect_uri, response_type){
                base()
                getToAuth()
            }
        })
        

        describe('when a request is missing client_id', function(){
             beforeEach(function(){
                req.query = { redirect_uri: uri, response_type: 'code'}
                req.url +=  format('?redirect_uri=%s&response_type=code', uri)
             })
            it('should send an error', function(){
                setup()
                sendError.should.be.an.oauthErrorResponse(errors.InvalidRequestError, 'client_id')
            });
        });

        describe('when a request as missing redirect_uri', function(){
            beforeEach(function(){
                req.query = { response_type: 'code', client_id: client}
                req.url +=  format('?client_id=%s&response_type=code', client)
            })

            it('should send an error', function(){
                setup()
                sendError.should.be.an.oauthErrorResponse(errors.InvalidRequestError, 'redirect_uri')
            });
        });

        describe('when a request is missing response_type', function(){
            beforeEach(function(){
                req.query = { redirect_uri: uri, client_id: client}
                req.url +=  format('?client_id=%s&redirect_uri=%s', uri, client)
            })
            it('should send an error', function(){
                setup()
                sendError.should.be.an.oauthErrorResponse(errors.InvalidRequestError, 'response_type')
            });
        });
   
        describe('when a request redirect_uri contains a hash fragment', function(){
            beforeEach(function(){
                req.query = { response_type: 'code', client_id: client, redirect_uri: 'https://c.c.com?hello#dfdsf' }
                req.url +=  format('?response_type=code&client_id=%s&redirect_uri=%s'
                    , client, encodeURIComponent('https://c.c.com?hello#dfdsf'))
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
                req.url +=  format('?response_type=boooom&client_id=%s&redirect_uri=%s', client, uri )
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
                req.url +=  format('?response_type=code&client_id=%s&redirect_uri=%s', client, uri )

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
                    req.url +=  format('?response_type=code&client_id=%s&redirect_uri=%s', client, uri )
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

    describe('when a request is intercepted', function(){
        beforeEach(function(){ 
            var base = setup;
            setup = function(){
                 base()
                 middleware(options)   
            }

            options.grants.push('authorization_code')
        })
       // console.log(req, res, next)
        describe('when the request is heading for the token endpoint', function(){
            beforeEach(function(){ 
                req.method = 'POST'
                req.url = tokenEndpoint
            })

            it('continue through for the token endpoint', function(){
                setup()
                next.should.have.been.calledOnce
                next.should.have.been.calledWithExactly()    
            })
        }) 
        
        describe('when the request is heading for the code endpoint', function(){
            beforeEach(function(){ 
                req.method = 'GET'
                req.url = authorizeEndpoint
            })

            it('continue through for the code endpoint', function(){
                setup()
                next.should.have.been.calledOnce
                next.should.have.been.calledWithExactly()    
            })

            describe('when the grant doesn\'t support auth code', function(){
                beforeEach(function(){ 
                    req.method = 'GET'
                    req.url = authorizeEndpoint
                    options.grants = ['client_credentials']
                })

                it('protect the code endpoint', function(){
                    setup()
                    next.should.not.have.been.called 
                })
            })
        }) 
       
        
        describe('when the request is missing an access_token', function(){

            it('should send an invalid_request error', function(){
                setup()
                sendError.should.have.been.an.oauthErrorResponse(errors.InvalidRequestError, 'access_token not included in the request')
            })
        }) 

        describe('when the request contains an access_token in more then one place', function(){
            beforeEach(function(){ 
                req.query.access_token ='token'
                req.body.access_token ='token'
            })

            it('should send an invalid_request error', function(){
                setup()
                sendError.should.have.been.an.oauthErrorResponse(errors.InvalidRequestError, 
                    'access_token can only be specified in either the: header, body, or query, once')
            })
        }) 

        describe('when the request doesn\'t contain a type', function(){
            beforeEach(function(){ 
                req.query.access_token ='token'
            })

            it('should send an invalid_request error', function(){
                setup()
                sendError.should.have.been.an.oauthErrorResponse(errors.InvalidRequestError, 
                    'token_type missing or invalid')
            })
        })

        describe('when the request validates correctly', function(){
            beforeEach(function(){ 
                req.query.access_token ='token'
                req.query.token_type ='bearer'
            })

            it('should pass the token to the hook', function(){
                setup()
                hooks.validateToken.should.have.been.calledWith('token')
            })

            describe('when the hook validates the token', function(){
                beforeEach(function(){ 
                    hooks.validateToken.yields(null, true)
                })

                it('should clear the request to the next in the chain', function(){
                    setup()
                    next.should.have.been.calledOnce
                    next.should.have.been.calledWithExactly()  
                })
            }) 

            describe('when the hook throws an error', function(){
                beforeEach(function(){ 
                    hooks.validateToken.yields(new Error())
                })

                it('should send the error back to the client', function(){
                    setup()
                    sendError.should.have.been.an.serverError(Error)
                })
            }) 

            describe('when the hook returns false', function(){
                beforeEach(function(){ 
                    hooks.validateToken.yields(null, false)
                })

                it('should send the error back to the client', function(){
                    setup()
                    sendError.should.have.been.an.oauthErrorResponse(errors.UnauthorizedClient)
                })
            }) 
        }) 
    })

})



function getGrantStubs(){
    return {
        grantToken: sinon.stub(),
        grantCode: sinon.stub(),
        resourceOwnerApproval: sinon.stub(),
        validateRequest: sinon.stub()
    }
}