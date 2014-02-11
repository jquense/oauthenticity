'use strict'
var  _ = require('lodash')
  , restify  = require('restify')
  , code   = require('./code.js')
  , resourceOwner = require('./resourceOwner.js')
  , clientCredentials = require('./clientCredentials.js')
  , common = require('./common');

var GRANTS = ['authorization_code', 'client_credentials', 'password', 'refresh_token']
  , REQURED_HOOKS = ['authenticateClient']
  , GRANTERS = {
        'authorization_code': code,
        'client_credentials': clientCredentials, 
        'password': resourceOwner, 
        'refresh_token': code
    };


module.exports = function setupOAuth(server, options){
    options = _.defaults(options || {}, {
        grants: ['authorization_code', 'implicit'],
        tokenEndpoint: '/token',
        authorizeEndpoint: '/authorize',
        realm: 'the porch',
        expire: Infinity,
        hooks: {}
    });

    if (!hasRequiredHooks(options.hooks, options.grants) )
        throw new Error('required hooks not met')

    server.post(options.tokenEndpoint, _.partialRight(grantToken, options));
    
    if ( _.contains(options.grants, 'authorization_code') )
        server.get(options.authorizeEndpoint, _.partialRight(requestDecision, options));
 
    server.use(_.partialRight(common.validateToken, options));
}

function grantToken(req, res, next, options){
    var supported = 'the supported grant_type are: ' + options.grants.join(', ')
      , grant = req.body.grant_type
      , client, clientSecret;
    
    if ( !_.isObject(req.body) ) 
        return next(new common.InvalidRequestError('Request has no Body.'))

    if ( req.body.grant_type === undefined)
        return next(new common.InvalidRequestError('No grant_type specified.'))

    else if ( !~options.grants.indexOf(grant) )
        return next(new common.UnsupportedGrantType(supported))

    if ( req.authorization && req.authorization.basic ){
        client = req.authorization.basic.username
        clientSecret = req.authorization.basic.password
    } else {
        client = req.body.client_id
        clientSecret = req.body.client_secret
    }

    options.hooks.authenticateClient(client, clientSecret, function(err, valid){
        var granter = GRANTERS[grant]
          , grantToken =  _.partialRight(granter.grantToken, options);

        if ( err ) next(err)
        if ( !valid ) return next(new common.InvalidClientError('invalid client'))

        granter.validateRequest(req, options)
            .then(grantToken)
            .then(function (tokens){
                res.cache( 'no-store')
                res.header('Pragma', 'no-cache')

                res.send(200, {
                    access_token: tokens.token,
                    refresh_token: tokens.refresh,
                    token_type: 'Bearer',
                    expires_in: _.isFinite(options.expires) ? options.expires : undefined 
                })
            })
    });
}

function requestDecision(req, res, next, options){
    var redirect = req.query.redirect_uri
      , responseType   = req.query.response_type
      , clientId = req.query.client_id
      , grantCode = _.partialRight(code.grantCode, redirect, responseType, clientId, options)
      , errors = [];

    _.each(['client_id', 'redirect_uri', 'response_type'], function(param){
        if ( req.query[param] === undefined )
            errors.push(param + ' is a required parameter');
    })

    if ( errors.length )
        return next(new common.InvalidRequestError(errors.join(' ')))

    if ( ~redirect.indexOf('#') )
        return next(new common.InvalidRequestError('redirect_uri cannot contain a hash (#) fragment.') )
      
    if ( responseType !== 'code' && responseType !== 'token')
        return next(new common.InvalidRequestError('the response_type must either be \'token\' or \'code\''))

    code.resourceOwnerApproval(req, res, clientId, options)
        .then(grantCode)
        .then(function(code){
            var frag = responseType === 'token' 
                ? '#access_token=' + code + '&token_type=bearer'
                : !!~redirect.indexOf('?')
                    ? '?' + 'code=' + code
                    : '&' + 'code=' + code;

            res.writeHead(302, { 'Location': redirect + frag })
            return res.end()
        }, next)
        .catch(next)
}



function hasRequiredHooks(hooks, grants){

    return _.every(grants, function(grant){
        var req = GRANTERS[grant.requiredHooks];

        if ( req && req.length)
            return _.intersection(req, hooks).length === req.length

        return true;
    })       
}



