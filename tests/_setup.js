var chai = require('chai')
  , chaiAsPromised = require('chai-as-promised')
  , sinonChai = require("sinon-chai")
  , Assertion = require("chai").Assertion

module.exports = function(){
    chai.use(chaiAsPromised);
    chai.use(sinonChai);
    chai.should();

    Assertion.addMethod("oauthError", function(Err, testBody){
        var obj = this._obj
          , assertion = this
          , isCtor = typeof Err === 'function'
          , name = isCtor ? (new Err()).name : 'undefined'
          , promise =  typeof this.then === "function" ? assertion : obj
          , derived;

        if (!isCtor ) throw new TypeError("you didn't provide a valid Ouath Error")

        derived = promise.then(function(value){
                assertion._obj = value;
                assertion.assert(false, "expected promise to be rejected with #{exp} but it was fulfilled with #{act}"
                    , null, name, value)

            }, function(reason){

                assertion.assert(
                      reason instanceof Err
                    , "expected promise to be rejected with #{exp} but it was rejected with #{act}"
                    , "expected promise not to be rejected with #{exp} but it was rejected with #{act}"
                    , name
                    , reason)

                assertion.assert(reason.message.indexOf(testBody) !== -1,
                    "expected promise to be rejected with an error including #{exp} but got #{act}",
                    "expected promise not to be rejected with an error including #{exp}",
                    testBody,
                    reason.message);
            })

        chaiAsPromised.transferPromiseness(this, derived)
    })
}