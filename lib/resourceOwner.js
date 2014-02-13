var _ = require('lodash')
  , errors = require('./errors')
  , common = require('./common');


module.exports = {

    requiredHooks: [ 'generateUserToken', 'generateRefreshToken' ],

    validateRequest: function(req, options){

        return new Promise(function(resolve, reject){
            var errs = [];

            _.each(['username', 'password'], function(param){
                if ( req.body[param] === undefined )
                    errs.push(param + ' is a required parameter');
            })

            if ( errs.length )
                return reject(new common.InvalidRequestError(errs.join(' ')))

            resolve({
                username: req.body.username,
                password: req.body.password,
            });
        })
        
    },

    grantToken: function (params, options) {
        var accessToken  = Promise.promisify(options.hooks.generateUserToken)
          , refreshToken = Promise.promisify(options.hooks.generateRefreshToken);

        return new Promise(function(resolve, reject){
            var finished = Promise.all([
                  accessToken(params.username, params.password)
                , refreshToken(params.username, params.password)])

            finished.spread(function(token, refresh){
                if ( !token )
                    return reject(new common.AccessDeniedError('server denied acces_token request'))

                resolve({
                    token: token,
                    refresh: refresh
                });
            }, reject)
        })
    }

}

function accumulate(times, fn){
    var results = [null]
      , done;

    return function(err, result){
        if ( done ) return;

        if ( err && !done ) {
            done = true;
            return fn(err)
        }

        results.push(result);

        if ( --times < 1 ) return fn.apply(this, results)
    }
}



