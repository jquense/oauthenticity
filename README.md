Existential
=====================

A simple, custimizable oauth2 provider for connect style node servers. Existential abstracts way the annoying validation and flow of the Oauth2 spec and lets you jsut plugin in your specific business logic. It is mean to be easy and only as opinonated as needed to still be oauth2

###Setup

Since we need to manually define endpoints (token and authorixation) there is a little more work needed then just providing a middleware. the
    require('existential').createServer
    
medthod will handle it all, just provide the necessary hooks, and grant types you wish to use
