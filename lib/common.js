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


function UnauthorizedClient(msg){
    if ( !(this instanceof UnauthorizedClient) ) return new UnauthorizedClient(msg);
    restify.UnauthorizedError.call(this, exports.errBody('invalid_request', msg))
}

function AccessDeniedError(msg){
    if ( !(this instanceof AccessDeniedError) ) return new AccessDeniedError(msg);
    restify.UnauthorizedError.call(this, exports.errBody('invalid_request', msg))
}

function InvalidRequestError(msg){
    if ( !(this instanceof InvalidRequestError) ) return new InvalidRequestError(msg);
    restify.BadRequestError.call(this, exports.errBody('invalid_request', msg))
}

function InvalidClientError(msg){
    if ( !(this instanceof InvalidClientError) ) return new InvalidClientError(msg);
    restify.BadRequestError.call(this, exports.errBody('invalid_request', msg))
}

function InvalidGrant(msg){
    if ( !(this instanceof InvalidGrant) ) return new InvalidGrant(msg);
    restify.BadRequestError.call(this, exports.errBody('invalid_request', msg))
}

function UnsupportedGrantType(msg){
    if ( !(this instanceof UnsupportedGrantType) ) return new UnsupportedGrantType(msg);
    restify.BadRequestError.call(this, exports.errBody('invalid_request', msg))
}

function InvalidScopeError(msg){
    if ( !(this instanceof InvalidRequestError) ) return new InvalidScopeError(msg);
    restify.InvalidScopeError.call(this, exports.errBody('invalid_request', msg))
}

function UnsupportedResponseTypeError(msg){
    if ( !(this instanceof UnsupportedResponseTypeError) ) return new UnsupportedResponseTypeError(msg);
    restify.BadRequestError.call(this, exports.errBody('invalid_request', msg))
}

util.inherits(UnauthorizedClient, restify.UnauthorizedError)
util.inherits(AccessDeniedError,  restify.UnauthorizedError)

util.inherits(InvalidRequestError,          restify.BadRequestError)
util.inherits(InvalidClientError,           restify.BadRequestError)
util.inherits(InvalidGrant,                 restify.BadRequestError)
util.inherits(UnsupportedGrantType,         restify.BadRequestError)
util.inherits(InvalidScopeError,            restify.BadRequestError)
util.inherits(UnsupportedResponseTypeError, restify.BadRequestError)

module.exports.UnauthorizedClient           = UnauthorizedClient
module.exports.AccessDeniedError            = AccessDeniedError

module.exports.InvalidRequestError          = InvalidRequestError
module.exports.InvalidClientError           = InvalidClientError
module.exports.InvalidGrant                 = InvalidGrant
module.exports.UnsupportedGrantType         = UnsupportedGrantType
module.exports.InvalidScopeError            = InvalidScopeError
module.exports.UnsupportedResponseTypeError = UnsupportedResponseTypeError

//TemporarilyUnavailableError: 'temporarily_unavailable',
//ServerError: 'server_error',