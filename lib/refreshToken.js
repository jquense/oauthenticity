var _ = require('lodash')
  , errors = require('./errors');


module.exports = {

    requiredHooks: [ 'generateUserToken', 'generateRefreshToken', 'exchangeRefreshToken' ],

    validateRequest: function(req, options){

        return new Promise(function(resolve, reject){

            if (req.body.refresh_token === undefined )
                return reject(new errors.InvalidRequestError(errors.join(' ')))

            resolve({
                refreshToken: req.body.refresh_token
            });
        })
        
    },

    grantToken: function (params, options) {
        var accessToken  = Promise.promisify(options.hooks.generateUserToken)
          , refreshToken = Promise.promisify(options.hooks.generateRefreshToken);

        return new Promise(function(resolve, reject){
            var finished = Promise.all([
                  accessToken(params.refresh_token, params.password)
                , refreshToken(params.refresh_token, params.password)])

            finished.spread(function(token, refresh){
                if ( !token )
                    return reject(new errors.AccessDeniedError('server denied acces_token request'))

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



