OAuthenticity.js [![Build Status](https://travis-ci.org/theporchrat/oauthenticity.png?branch=master)](https://travis-ci.org/theporchrat/oauthenticity)
=====================

A simple, customizable oauth2 provider for connect style node servers. Existential abstracts way the annoying validation
and flow of the Oauth2 spec and lets you just plugin in your specific business logic. It is mean to be easy and only
as opinionated as needed to still be oauth2

###Use

The actual creation of an `oauth2` provider is fairly trivial. Rather then automatically adding routes, and middleware
the `createOauth2Provider()` method will return a set of functions that do the necessary work. This decouples `oauthenticity`
from any specific web server implementation

    var oauth2Provider = require('oauthenticity')
      , routes;

    routes = oauth2provider.createOauth2Provider(options)
    /*
        routes => {
            middleware:            fn -> (req, res, cb)
            tokenEndpoint:         fn -> (req, res, cb)
            authorizationEndpoint: fn -> (req, res, cb)
        }
    */

All returned function have the same signature, each takes a node `request`, `response` object, and a third `cb` or callback
function. this should look familiar to anyone using Express or Restify, which allows you to simply pass the
functions to the routes and middleware chain

    server.use(routes.middleware)
    server.post('/token', routes.tokenEndpoint)
    server.get('/authorization', routes.authorizationEndpoint)

you can also use oauthenticity without any particular web framework as well.

### Caveats

OAuthenticity expects the request object to have a parsed `body` and `query` object. If using restify or express make sure
to include these middlewares.

## Options

 - `grants`: (Array) specify which grants you wish to use es: `["authorization_grant", "password"]`
 - `allowImplicit`: (Boolean) whether to allows implicit token granting, for the `authorization_code` grant. If `true`
    you will be able to do `response_type=token` when making a request to the authorization endpoint
 - `tokenEndpoint:` (String) the route path that grants tokens ex: '/token',
 - `authorizeEndpoint:` (String) the route path that grants auth codes
    (or tokens if `allowImplicit` is true) ex: '/authorize'
 - `realm`: (String) 'the porch'
 - `hooks`: object: see below

## Hooks

Hooks are a set of functions that you insert your application logic into the auth process. OAuthenticity will call the appropriate hook
when it needs information. It is up to you to generate and store tokens, validate the requesting client/resource owner etc.
Each grant type requires a different set of hooks, although there is some overlap.

### Authorization Code

    {
        generateUserToken: function(resourceOwner, null, cb ){
            //create access_token
            cb(null, accessToken)
        },
        generateRefreshToken: function ( resourceOwner, null, cb ) {
            //create refresh_token
            cb(null, refreshToken)
        }
        generateCode: function (resourceOwner, clientId, redirectUri, cb ) {
            // generate an auth code that expires. you will need to store all the arguments to return later
            cb(null, code)
        },
        validateAuthCode: function ( code, cb ) {
            //validate code and return:
            cb(null, valid, clientId, redirectUri, resourceOwner)
        },
        userAuthorization: function ( req, res, clientId, redirect_uri, cb ) {
            // validate resource owner:
            // you can use the res/req objects to redirect to a login if needed
            cb(null, user)
        }
    }

### Password

    {
        generateUserToken: function(resourceOwner, password, cb ){
            //create access_token
            cb(null, accessToken)
        },

        generateRefreshToken: function ( resourceOwner, password, cb ) {
            //create refresh_token
            cb(null, refreshToken)
        }
    }

### Refresh Token

    {
        generateUserToken: function(refreshToken, null, cb ){
            //create access_token
            cb(null, accessToken)
        },

        generateRefreshToken: function ( refreshToken, null, cb ) {
            //create refresh_token
            cb(null, refreshToken)
        },

    }

### Known Issues

only authorization_grant, password, and refresh_token grants are actually implemented
