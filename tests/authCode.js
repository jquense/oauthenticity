
require('./_setup')()

var Promise  = require('bluebird')
  , _ = require('lodash')
  , sinon    = require("sinon")
  , authCode = require('../lib/code.js')
  , common   = require('../lib/common.js')
  ;

//Promise.onPossiblyUnhandledRejection(function(){})
function req(client, uri, code){
    return {
        body:{
            client_id: client,
            redirect_uri: uri,
            code: code    
        }      
    }
}


describe('when the grant is authorization_code', function(){
    var validate = authCode.validateRequest
      , client = 'the_porch', uri = 'my.example.com', code = 'secret!'
      , result = { client_id: client, redirect_uri: uri, code: code, resourceOwner: 'bob' }

    describe('when an invalid request is sent', function(){
        var options = { hooks: {} };

        describe('when a request as missing parameters', function(){

            it('should fail with invalid_request and proper message', function(done){
                Promise.all([
                    validate(req(undefined, uri, code), options)
                        .should.be.an.oauthError(common.InvalidRequestError, 'client_id'),

                    validate(req(client, undefined, code), options)
                        .should.be.an.oauthError(common.InvalidRequestError, 'redirect_uri'),

                    validate(req(client, uri, undefined), options)
                        .should.be.an.oauthError(common.InvalidRequestError, 'code'),

                ]).should.notify(done)

            });
        });

        describe('when a code is validated', function(){
            var request = req(client, uri, code), generateCode;
            
            beforeEach(function(){
                options.hooks.validateAuthCode = generateCode = sinon.stub()  
                validate = _.partial(authCode.validateRequest, request, options)
                generateCode.yields(null, code, client, uri, 'bob')   
            })


            it('should call the hook', function(done){
                validate().then(function(){
                    generateCode.should.have.been.calledWith(code)
                })
                .should.notify(done)
            });

            it('should return the right params', function(done){
                validate().should.become({ 
                    redirect_uri: uri,
                    client_id: client,
                    code: code,
                    resourceOwner: 'bob' 
                })
                .and.notify(done)
            });

            describe('when a the hook returns missing information', function(){
                beforeEach(function(){
                    generateCode.yields(null, code)   
                })

                it('should throw and error', function(done){
                    validate().should.be.rejectedWith(TypeError, 'the \'validateAuthCode\' hook must return with an error,' + 
                        ' false, or with code, cleint_id, redirect_uri, and resourceOwner')
                        .and.notify(done)
                });
            })

            describe('when a code is not returned', function(){
                beforeEach(function(){
                    generateCode.yields(null, false)   
                })

                it('should fail with invalid_request', function(done){
                    validate().should.be.an.oauthError(common.InvalidRequestError, 'the code provided was invalid')
                        .and.notify(done)
                });
            })

            describe('when an error is returned', function(){
                beforeEach(function(){
                    generateCode.yields('my error')   
                })

                it('should pass the error forward', function(done){
                    validate().should.be.rejectedWith('my error').and.notify(done)
                });
            })


            describe('when the code doesn\'t validate request_uri', function(){
                beforeEach(function(){
                    generateCode.yields(null, code, client, 'another one', 'bob')   
                })

                it('should be return an invalid_request', function(done){
                    validate().should.be.an.oauthError(common.InvalidRequestError, 'request_uri do not match')
                        .and.notify(done)
                });
            })

            describe('when the code doesn\'t validate client_id', function(){
                beforeEach(function(){
                    generateCode.yields(null, code, 'another one', uri, 'bob')   
                })

                it('should be return an invalid_request', function(done){
                    validate().should.be.an.oauthError(common.InvalidRequestError, 'invalid client_id')
                        .and.notify(done)
                });
            })


            
        })

    })

    describe('when an a code is exchanged for a token', function(){
        var options, generateUserToken, generateRefreshToken, grantTokens;

        beforeEach(function(){
            generateUserToken = sinon.stub(),
            generateRefreshToken = sinon.stub() 
            options = { hooks:
                 { generateRefreshToken: generateRefreshToken, generateUserToken: generateUserToken} }

            grantTokens = _.partial(authCode.grantToken, result, options)
        })

        describe('when it returns true', function(){
            beforeEach(function(){
                generateUserToken.yields(null, true)   
                generateRefreshToken.yields(null, true) 
            })

            it('should call hooks correctly', function(done){
                grantTokens()
                    .then(function(){
                        generateUserToken.should.have.been.calledWith('bob', null)   
                        generateRefreshToken.should.have.been.calledWith('bob', null) 
                    })
                    .should.notify(done)
            })

            describe('when it returns an access token', function(){
                beforeEach(function(){
                    generateUserToken.yields(null, 'token')   
                    generateRefreshToken.yields(null, 'refresh') 
                })

                it('should return it with the refresh token', function(done){
                    grantTokens().should.become({ token: 'token', refresh: 'refresh' }).and.notify(done)     
                })

                describe('when it doesn\'t return a refresh token', function(){
                    beforeEach(function(){ generateRefreshToken.yields(null, false) })

                    it('should return undefined', function(done){
                        grantTokens().should.become({ token: 'token', refresh: undefined }).and.notify(done)     
                    })
                })
            })

        })

        describe('when it returns false', function(){
            beforeEach(function(){
                generateRefreshToken.yields(null, 'refresh_token') 
            })

            describe('when it returns without a token', function(){
                beforeEach(function(){
                    generateUserToken.yields(null, false)  
                })

                it('should deny access', function(done){
                    grantTokens().should.be.an.oauthError(common.AccessDeniedError, 'server denied acces_token request')
                        .and.notify(done)
                })
            })

            describe('when access token returns an error', function(){
                beforeEach(function(){
                    generateUserToken.yields('my error')  
                })

                it('should pass on it\'s error', function(done){
                    grantTokens().should.be.rejectedWith('my error').and.notify(done)
                })

                describe('when refresh token returns false', function(){
                    beforeEach(function(){
                        generateRefreshToken.yields(null, false)  
                    })

                    it('should still fail and pass on error', function(done){
                        grantTokens().should.be.rejectedWith('my error').and.notify(done)
                    })
                })
            })

            describe('when refresh token returns an error', function(){
                beforeEach(function(){
                    generateRefreshToken.yields('my error')  
                })

                it('should pass on error', function(done){
                    grantTokens().should.be.rejectedWith('my error').and.notify(done)
                })
            })
        })
    })

    describe('when an a code is requested', function(){
        var options, generateToken, generateCode
          , token = 'token'

        beforeEach(function(){
            generateToken = sinon.stub(),
            generateCode = sinon.stub() 
            options = { allowImplicit: true, hooks:
                 { generateCode: generateCode, generateUserToken: generateToken} }
        })

        describe('when the request_type is invalid', function(){
            beforeEach(function(){
                grantCode = _.partial(authCode.grantCode, 'bob', uri, 'invalid_type', client, options)
            })

            it('should deny reject the request', function(done){
                grantCode().should.be.an.oauthError(common.InvalidRequestError, 'response_type must be either: \'token\' or \'code\'')
                    .and.notify(done)
            })
        })

        describe('when the request_type is token', function(){
            beforeEach(function(){
                grantCode = _.partial(authCode.grantCode, 'bob', uri, 'token', client, options)
            })

            describe('when the implict not allowed', function(){
                beforeEach(function(){
                    options.allowImplicit = false
                    grantCode = _.partial(authCode.grantCode, 'bob', uri, 'invalid_type', client, options)
                })

                it('should deny reject the request', function(done){
                    grantCode().should.be.an.oauthError(common.InvalidRequestError, 'response_type must be either: \'token\' or \'code\'')
                        .and.notify(done)
                })

            })

            describe('when the grantToken returns true ', function(){
                beforeEach(function(){
                    generateToken.yields(null, token)
                })

                it('should call the token hook', function(done){

                    grantCode()
                        .then(function(){
                            generateCode.should.not.have.been.called
                            generateToken.should.have.been.calledOnce
                            generateToken.should.have.been.calledWith('bob', null)
                        })
                        .should.notify(done)
                })  
            
                it('should call return a token', function(done){
                    grantCode().should.become(token).and.notify(done)
                })
            })

            describe('when the grantToken returns false ', function(){
                beforeEach(function(){
                    generateToken.yields(null, false)
                })

                it('should deny access', function(done){
                    grantCode().should.be.an.oauthError(common.AccessDeniedError, 'server denied acces_token request')
                        .and.notify(done)
                })  
            })

            describe('when the grantToken returns an error', function(){
                beforeEach(function(){
                    generateToken.yields('my error')
                })

                it('should pass the error up', function(done){
                    grantCode().should.be.rejectedWith('my error').and.notify(done)
                })  
            })
        })

        describe('when the request_type is code', function(){
            beforeEach(function(){
                grantCode = _.partial(authCode.grantCode, 'bob', uri, 'code', client, options)
            })

            describe('when the grantCode returns true ', function(){
                beforeEach(function(){
                    generateCode.yields(null, code)
                })

                it('should call the token hook', function(done){

                    grantCode()
                        .then(function(){
                            generateToken.should.not.have.been.called
                            generateCode.should.have.been.calledOnce
                            generateCode.should.have.been.calledWith('bob', client)
                        })
                        .should.notify(done)
                })  
            
                it('should call return a code', function(done){
                    grantCode().should.become(code).and.notify(done)
                })
            })

            describe('when the grantCode returns false ', function(){
                beforeEach(function(){
                    generateCode.yields(null, false)
                })

                it('should deny access', function(done){
                    grantCode().should.be.an.oauthError(common.AccessDeniedError, 'server denied code request')
                        .and.notify(done)
                })  
            })

            describe('when the grantCode returns an error', function(){
                beforeEach(function(){
                    generateCode.yields('my error')
                })

                it('should pass the error up', function(done){
                    grantCode().should.be.rejectedWith('my error').and.notify(done)
                })  
            })
        })
    })

    describe('when user authorization is requested', function(){
        var options = { hooks: {} }
          , userAuth, requestApproval, res, req;
    
        beforeEach(function(){
            res = {}; req = { url: '/authorize' };
            userAuth = sinon.stub();
            options = { hooks: { userAuthorization: userAuth } }
            requestApproval = _.partial(authCode.resourceOwnerApproval, req, res, client, options)
            userAuth.yields(null, 'bob')
        })

        it('should call hook appropriately', function(done){

            requestApproval().then(function(){
                userAuth.should.have.been.calledOnce
                userAuth.should.have.been.calledWith(req, res, client)
            }).should.notify(done) 
        })

        it('should return with a resource owner', function(done){

            requestApproval().should.become('bob').and.notify(done) 
        })

        describe('when it returns false', function(){
            beforeEach(function(){
                userAuth.yields(null, false)
            })

            it('should deny access', function(done){
                requestApproval().should.be.an.oauthError(common.AccessDeniedError, 'server denied authorization request')
                    .and.notify(done)    
            })
        })

        describe('when it returns an error', function(){
            beforeEach(function(){
                userAuth.yields('my error')
            })
            
            it('should pass the error back up', function(done){
                requestApproval().should.be.rejectedWith('my error')
                    .and.notify(done)    
            })
        })
    })
})



