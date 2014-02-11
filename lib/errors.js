var _ = require('lodash')
  , restify  = require('restify')
  , util = require('util')
  , crypto = require('crypto');




function getUser(username){
    return User.findOne({ username: username }).exec()
}


exports.generateToken = function generateToken(data) {
    var random = Math.floor(Math.random() * 100001)
      , timestamp = (new Date()).getTime()
      , sha256 = crypto.createHmac('sha256', random + timestamp + 'porchrat')

    return sha256.update(data).digest('base64');
}

exports.validateToken = function (req, res, next, options) {
    var requestingToken = req.method === 'POST' && req.path() === options.tokenEndpoint
      , auth = req.authorization
      , inHeader = auth.scheme && auth.credentials
      , inQuery  = req.query.token_type && req.query.access_token
      , inBody   = req.body.token_type  && req.body.access_token
      , token;

    if ( req.route.auth === false || requestingToken ) return next();

    if ( inHeader + inBody + inQuery !== 1 )
        return next( exports.InvalidRequestError('token specified cannot be specified in the header and query string' ));
    
    token = inHeader
        ? auth.credentials
        : inQuery 
            ? req.query.access_token
            : req.body.access_token
  
    options.hook.validateToken(token, function(err, valid){
        if ( err )   return next(err);
        if ( valid ) return next();

        res.header('Link',
                '<' + options.tokenEndpoint + '>; rel=\'oauth2-token\'; ' +
                'grant-types=\'client_credentials\'; token-types=\'bearer\'');

        res.header('WWW-Authenticate',
            'Bearer realm=\'' + options.realm + '\', ' +
            'error=\'401\', ' +
            'error_description=\'Client not authorized\'')

        res.send(new exports.UnauthorizedClient('Client not authorized') ); 
    });
}

exports.errBody = function(type, desc){
    return {
        message: desc, 
        body: {
            error: type,
            error_description: desc
        }    
    }
}


_.each({
        UnauthorizedClient:'unauthorized_client',
        AccessDeniedError: 'access_denied',
    }, function(item, key){

        module.exports[key] = function(msg){
            return new restify.UnauthorizedError(exports.errBody(item, msg))
        }
    });


_.each({
        InvalidRequestError: 'invalid_request',
        InvalidClientError: 'invalid_client',
        InvalidGrant: 'invalid_grant',
        UnsupportedGrantType: 'unsupported_grant_type',
        InvalidScopeError: 'invalid_scope',
        UnsupportedResponseTypeError: 'unsupported_response_type',
    }, function(item, key){

        module.exports[key] = function(msg){
            return new restify.BadRequestError(exports.errBody(item, msg))
        }
    });

//function InvalidRequestError(msg){
//    exports.errBody('invalid_request', msg)
//}

//util.inherits(InvalidRequestError, BadRequestError)

//TemporarilyUnavailableError: 'temporarily_unavailable',
//ServerError: 'server_error',