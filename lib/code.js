var _ = require('lodash')
  , url = require('url')
  , restify = require('restify')
  , common  = require('./common')
  , Promise = require('bluebird');

module.exports = {
    requiredHooks: [ 'generateUserToken', 'generateRefreshToken', 'generateCode', 'userAuthorization' ],

    validateRequest: function(req, options){
        var errors = []
          , getCode  = options.hooks.validateAuthCode;

        return new Promise(function(resolve, reject){
            var code = req.body.code;

            _.each(['client_id', 'redirect_uri', 'code'], function(param){
                if ( req.body[param] === undefined )
                    errors.push(param + ' is a required parameter');
            })

            if ( errors.length )
                return reject(new common.InvalidRequestError(errors.join(' ')))

            getCode(code, function(err, authCode, clientId, redirectUri, resourceOwner){
                if (err) reject(err)
                if ( !authCode ) 
                    return reject(new common.InvalidRequestError('the code provided was invalid'))

                if ( arguments.length !== 5 || !clientId || !redirectUri || !resourceOwner)
                    reject(new TypeError('the \'validateAuthCode\' hook must return with an error, false, or with code, cleint_id, redirect_uri, and resourceOwner'))

                if ( redirectUri !== req.body.redirect_uri) 
                    return reject(new common.InvalidRequestError('request_uri do not match'))

                if ( clientId !== req.body.client_id)
                    return reject(new common.InvalidRequestError('invalid client_id'))

                resolve({
                    client_id: req.body.client_id,
                    redirect_uri: req.body.redirect_uri,
                    code: code,
                    resourceOwner: resourceOwner,           
                });
            })

            
        })
        
    },

    grantCode: function(resourceOwner, redirectUri, responseType, clientId, options){

        return new Promise(function(resolve, reject){
            var generateCode  = options.hooks.generateCode
              , generateToken = options.hooks.generateUserToken
              , key = resourceOwner + ':' + clientId;

            if ( options.allowImplicit && responseType === 'token') {
                generateToken(resourceOwner, null, function(err, token){
                    if (err) return reject(err)

                    if ( !token )
                         return reject(new common.AccessDeniedError('server denied acces_token request'))

                    resolve(token);
                })

            } else if ( responseType === 'code' )  {
                generateCode(resourceOwner, clientId, function(err, code){
                    if (err) return reject(err)
                    if ( !code ) return reject(new common.AccessDeniedError('server denied code request'))

                    resolve(code);    
                })
            } else {
                return reject(new common.InvalidRequestError('response_type must be either: \'token\' or \'code\' '))
            }

        })
    },

    grantToken: function (params, options) {
        var accessToken  = Promise.promisify(options.hooks.generateUserToken)
          , refreshToken = Promise.promisify(options.hooks.generateRefreshToken);

        return new Promise(function(resolve, reject){
            var finished = Promise.all([
                      accessToken(params.resourceOwner, null).catch(reject)
                    , refreshToken(params.resourceOwner, null).catch(reject)])


            finished.spread(function(token, refresh){
                if ( !token )
                    return reject(new common.AccessDeniedError('server denied acces_token request'))

                resolve({
                    token: token,
                    refresh: refresh || undefined
                });
            }, reject)

        })
    },

    resourceOwnerApproval: function(req, res, clientId, options){
        var userAuth = options.hooks.userAuthorization;

        //function redirect(url){
        //    var next = 'next=' + (new Buffer(req.url)).toString('base64')
        //      , hasQuery = !url.parse(url).query

        //    url += hasQuery ? next : '?' + next

        //    res.writehead(302,{ 'Location': url })
        //    res.end()
        //}

        return new Promise(function(resolve, reject){
            userAuth( req, res, clientId, function (err,  user){
                if ( err ) return reject(err)
                if ( !user ) return reject(new common.AccessDeniedError('server denied authorization request'));

                resolve(user);
            })
        })
    }
}



function clearCode(key, ttl){
    return setTimeout(function(){
        delete codes[key];
    }, 600 * 1000)
}

