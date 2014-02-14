var _ = require('lodash')
  , util = require('util');


function OAuthError(code, err, desc){
    this.statusCode = code
    this.message = desc;
    this.body = {
        error: err,
        error_description: desc    
    }
    
    this.contentLength = Buffer.byteLength(JSON.stringify(this.body))
    this.name = 'OAuthError'
}

_.each({
        InvalidRequestError: 'invalid_request',
        InvalidClientError: 'invalid_client',
        InvalidGrant: 'invalid_grant',
        UnsupportedGrantType: 'unsupported_grant_type',
        InvalidScopeError: 'invalid_scope',
        UnsupportedResponseTypeError: 'unsupported_response_type',
    }, function(item, key){

        module.exports[key] = function(msg){
            OAuthError.call(this, 400, item, msg)
        }

        util.inherits(module.exports[key], OAuthError)
    });

_.each({
        AccessDeniedError:  'access_denied',
        UnauthorizedClient: 'unauthorized_client',

    }, function(item, key){

        module.exports[key] = function(msg){
            OAuthError.call(this, 401, item, msg)
        }

        util.inherits(module.exports[key], OAuthError)
    });