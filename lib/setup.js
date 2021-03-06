﻿'use strict'
var  _ = require('lodash')
  , url = require('url')
  , code   = require('./code.js')
  , resourceOwner = require('./resourceOwner.js')
  , clientCredentials = require('./clientCredentials.js')
  , errors = require('./errors');

var GRANTS = {
        'authorization_code': code,
        'client_credentials': clientCredentials, 
        'password': resourceOwner, 
        'refresh_token': code
    };


module.exports.createOauth2Provider = function setupOAuth( options ){
    var grants = {}

    options = _.defaults(options || {}, {
        grants: [ 'authorization_code' ],
        allowImplicit: false,
        tokenEndpoint: '/token',
        authorizeEndpoint: '/authorize',
        realm: 'the porch',
        expire: Infinity,
        hooks: {}
    });

    grants = _.pick.apply(_, [ GRANTS ].concat(options.grants))

    return exports._setupServer( options, grants);
}

module.exports._setupServer = function( options, grants){
    var routes = {};

    if ( !hasRequiredHooks(options.hooks, options.grants) )
        throw new Error('required hooks not met')

    routes.middleware = _.partialRight(exports.validateToken, options);

    routes.tokenEndpoint = _.partialRight(grantToken, options, grants)

    if ( _.contains(options.grants, 'authorization_code') )
        routes.authorizationEndpoint = _.partialRight(requestDecision, options, grants);

    return routes;
}

function grantToken(req, res, next, options, grants){
    var supported = 'the supported grant_type are: ' + options.grants.join(', ')
      , grantType = req.body && req.body.grant_type
      , sendError = _.partialRight(exports._respondWithError, res )
      , sendJson  = _.partialRight(exports._sendJson, res )
      , client, clientSecret;
    
    if ( !_.isObject(req.body) ) 
        return sendError(new errors.InvalidRequestError('Request has no Body.'))
    
    if ( req.body.grant_type === undefined)
        return sendError(new errors.InvalidRequestError('No grant_type specified.'))
    
    else if ( !~options.grants.indexOf(grantType) )
        return sendError(new errors.UnsupportedGrantType(supported))

    if ( req.authorization && req.authorization.basic ){
        client = req.authorization.basic.username
        clientSecret = req.authorization.basic.password
    } else {
        client = req.body.client_id
        clientSecret = req.body.client_secret
    }

    if (req.authorization && req.authorization.basic && req.body.client_id)
        return sendError(new errors.InvalidRequestError(
            'you cannot put client authorization in more then one place.'))

    options.hooks.authenticateClient(client, clientSecret, function(err, valid){
        var grant = grants[grantType]
          , grantToken = _.partialRight(grant.grantToken, options);

        if ( err )    return sendError(err)
        if ( !valid ) return sendError(new errors.InvalidClientError('invalid client'))

        grant.validateRequest(req, options)
            .then(grantToken)
            .then(function (tokens){
                
                res.setHeader( 'Cache-Control', ['no-cache', 'no-store'])
                res.setHeader('Pragma', 'no-cache')

                sendJson(200, {
                    access_token: tokens.token,
                    refresh_token: tokens.refresh,
                    token_type: 'Bearer',
                    expires_in: _.isFinite(options.expires) ? options.expires : undefined 
                })
            })
            .catch(sendError)
    });
}

function requestDecision(req, res, next, options, grants){
    var authCode     = grants.authorization_code
      , redirect     = req.query.redirect_uri
      , responseType = req.query.response_type
      , clientId     = req.query.client_id
      , sendError    = _.partialRight(exports._respondWithError, res )
      , grantCode    = _.partialRight(authCode.grantCode, redirect, responseType, clientId, options)
      , errs         = [];

    _.each(['client_id', 'redirect_uri', 'response_type'], function(param){
        if ( req.query[param] === undefined )
            errs.push(param + ' is a required parameter');
    })
    
    if ( errs.length )
        return sendError(new errors.InvalidRequestError(errs.join(' ')))
    
    if ( ~redirect.indexOf('#') ){
        return sendError(new errors.InvalidRequestError('redirect_uri cannot contain a hash (#) fragment.') )
    }
    
    if ( responseType !== 'code' && responseType !== 'token')
        return sendError(new errors.InvalidRequestError('the response_type must either be \'token\' or \'code\''))
    
    authCode
        .resourceOwnerApproval(req, res, clientId, redirect, options)
        .then(grantCode)
        .then(function(code){
            var frag = responseType === 'token' 
                ? '#access_token=' + code + '&token_type=bearer'
                : !~redirect.indexOf('?')
                    ? '?' + 'code=' + code
                    : '&' + 'code=' + code;

            res.writeHead(302, { 'Location': redirect + frag })
            return res.end()
        })
        .catch(function(err){
            exports._respondWithError(err, res, redirect)
        })
}

module.exports.validateToken = function (req, res, next, options) {
    var path = url.parse(req.url ).pathname
      , requestingToken = req.method === 'POST' && path === options.tokenEndpoint
      , requestingCode  = req.method === 'GET'  && path === options.authorizeEndpoint
      , sendError       = _.partialRight(exports._respondWithError, res )
      , auth     = req.authorization || {}
      , inHeader = !!(auth.credentials)
      , inQuery  = !!(req.query && req.query.access_token)
      , inBody   = !!(req.body  && req.body.access_token)
      , token_type = inHeader ? auth.scheme : inBody ? req.body.token_type : req.query.token_type
      , token;

    //console.log(requestingCode, options.grants )

    if ( requestingToken || (requestingCode && _.contains(options.grants, 'authorization_code') )) 
        return next();
    
    if ( inHeader + inBody + inQuery === 0 )
        return sendError(new errors.InvalidRequestError(
            'access_token not included in the request' ))

    else if ( inHeader + inBody + inQuery > 1 )
        return sendError(new errors.InvalidRequestError(
            'access_token can only be specified in either the: header, body, or query, once' ))

    if ( !token_type || token_type.toLowerCase() !== 'bearer' )
        return sendError(new errors.InvalidRequestError('token_type missing or invalid' ))

    token = inHeader
        ? auth.credentials
        : inQuery 
            ? req.query.access_token
            : req.body.access_token
  
    options.hooks.validateToken(token, function(err, valid){
        if ( err )   return sendError(err);
        if ( valid ) return next();

        res.setHeader('Link',
                '<' + options.tokenEndpoint + '>; rel=\'oauth2-token\'; ' +
                'grant-types=\'' + options.grants.join(', ') +'\'; token-types=\'bearer\'');

        res.setHeader('WWW-Authenticate',
            'Bearer realm=\'' + options.realm + '\', ' +
            'error=\'401\', ' +
            'error_description=\'Client not authorized\'')

        sendError(new errors.UnauthorizedClient('Client not authorized')); 
    });
}


module.exports._sendJson = function sendJson(code, obj, res){
    var body = JSON.stringify(obj)

    res.writeHead(code, {
        'Content-Type': 'application/json',
        'Content-Length' : Buffer.byteLength(body),
        'Connection': 'close'
    })
    res.end(body)
}

module.exports._respondWithError = function respondWithError(error, res, redirect){
    var code = error.statusCode || 500
      , body = error.body || error.message || error
      , contentType = 'text/plain'
      , len = error.contentLength

    if (redirect){
        var hasQuery = redirect.indexOf('?') !== -1
          , frag = (hasQuery ? '':'?' ) +
                'error=' + (body.error || 'server') +
                '&error_description=' + (body.error_description || body);

        res.writeHead(302, { 'Location': redirect + frag })
        res.end()
    } else {
        if ( typeof body === 'object'){
            contentType = 'application/json'
            body =  JSON.stringify(body)
        }
        res.writeHead(code, {
            'Content-Type': contentType,
            'Content-Length' : len || Buffer.byteLength(body),
            'Connection': 'close'
        })
        res.end(body)
    }
}

function hasRequiredHooks(hooks, grants){

    return _.every(grants, function(grant){
        var req = GRANTS[grant.requiredHooks];

        if ( req && req.length)
            return _.intersection(req, hooks).length === req.length

        return true;
    })       
}