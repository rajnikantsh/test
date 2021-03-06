var express = require('express');
var router = express.Router();
var jwt = require('jsonwebtoken');

var passportLinkedIn = require('../auth/linkedin').passport;
var passportGithub = require('../auth/github').passport;
var passportTwitter = require('../auth/twitter').passport;
var passportFacebook = require('../auth/facebook').passport;
var passportTumblr = require('../auth/tumblr').passport;
var passportYahoo = require('../auth/yahoo').passport;
var passportGoogle = require('../auth/google').passport;
var passportWindowsLive = require('../auth/windowslive').passport;
var passportDropbox = require('../auth/dropbox').passport;
var passportIdp1 = require('../auth/idp1').passport
var logger = require("../utils/logger");

var validateToken = function(req, res, next) {

    var token = req.body && req.body.token || req.params && req.params.token || req.headers['x-access-token'];
    if (token) {
        // verifies secret and checks expiration of token
        jwt.verify(token, global.applicationSecretKey, function(err, decoded) {
            if (err) {
                return res.json({
                    success: false,
                    message: 'Failed to authenticate token.'
                });
            } else {
                // if everything is good, save to request for use in other routes
                req.decoded = decoded;
                return next();
            }
        });

    } else {

        // if there is no token
        // returning an error
        return res.redirect(global.config.applicationStartpoint + '?failure=No token provided');
    }
};

var callbackResponse = function(req, res) {
    if (!req.user) {
        return res.redirect(global.config.applicationStartpoint + '?failure=Unauthorized');
    }
    logger.log('info', 'User authenticated with: ' + req.user.provider + 'Strategy with userid: ' + req.user.id);
    logger.sendMQMessage('info: User authenticated with: ' + req.user.provider + 'Strategy with userid: ' + req.user.id);
    var queryUserString = encodeURIComponent(JSON.stringify(req.user));
    return res.redirect(global.config.applicationEndpoint + '?user=' + queryUserString);
};

router.get('/', function(req, res, next) {
    res.render('index', {
        title: 'Node-Passport'
    });
});

router.get('/login', function(req, res, next) {
    res.redirect(global.config.applicationStartpoint + '?failure=Go back and register!');
});

//=================== linkedin =================
router.get('/auth/linkedin/callback',
    passportLinkedIn.authenticate('linkedin', {
        failureRedirect: '/passport/login'
    }),
    callbackResponse);

router.get('/auth/linkedin/:token',
    validateToken,
    passportLinkedIn.authenticate('linkedin'));

//===================== github =================
router.get('/auth/github/callback',
    passportGithub.authenticate('github', {
        failureRedirect: '/passport/login'
    }),
    callbackResponse);

router.get('/auth/github/:token',
    validateToken,
    passportGithub.authenticate('github', {
        scope: ['user:email']
    }));

//==================== twitter =================
router.use('/auth/twitter/callback',
    passportTwitter.authenticate('twitter', {
        failureRedirect: '/passport/login'
    }),
    callbackResponse);

router.get('/auth/twitter/:token',
    validateToken,
    passportTwitter.authenticate('twitter'));

//==================== facebook ================
router.get('/auth/facebook/callback',
    passportFacebook.authenticate('facebook', {
        failureRedirect: '/passport/login'
    }),
    callbackResponse);

router.get('/auth/facebook/:token',
    validateToken,
    passportFacebook.authenticate('facebook', {
        scope: ['email']
    }));

//===================== tumblr =================
router.get('/auth/tumblr/callback',
    passportTumblr.authenticate('tumblr', {
        failureRedirect: '/passport/login'
    }),
    callbackResponse);

router.get('/auth/tumblr/:token',
    validateToken,
    passportTumblr.authenticate('tumblr'));

//===================== yahoo =================
router.get('/auth/yahoo/callback',
    passportYahoo.authenticate('yahoo', {
        failureRedirect: '/passport/login'
    }),
    callbackResponse);

router.get('/auth/yahoo/:token',
    validateToken,
    passportYahoo.authenticate('yahoo'));

//===================== google =================
router.get('/auth/google/callback',
    passportGoogle.authenticate('google', {
        failureRedirect: '/passport/login'
    }),
    callbackResponse);

router.get('/auth/google/:token',
    validateToken,
    passportGoogle.authenticate('google', {
        scope: ['profile', 'email']
    }));

//================== windowslive ===============
router.get('/auth/windowslive/callback',
    passportWindowsLive.authenticate('windowslive', {
        failureRedirect: '/passport/login'
    }),
    callbackResponse);

router.get('/auth/windowslive/:token',
    validateToken,
    passportWindowsLive.authenticate('windowslive'));

//================== dropbox ==================
router.get('/auth/dropbox/callback',
    passportDropbox.authenticate('dropbox', {
        failureRedirect: '/passport/login'
    }),
    callbackResponse);

router.get('/auth/dropbox/:token',
    validateToken,
    passportDropbox.authenticate('dropbox'));

//===================saml ==================== 
router.post('/auth/idp1/callback', 
    passportIdp1.authenticate('saml', { 
        failureRedirect: '/passport/login' 
    }), 
    callbackResponse); 
 
router.get('/auth/idp1/:token', 
    validateToken, 
    passportIdp1.authenticate('saml',{ 
        scope : ['email'] 
})); 
//======== catch 404 and forward to login ========
router.all('/*', function(req, res, next) {
    var err = new Error('Not Found');
    err.status = 404;
    res.redirect(global.config.applicationStartpoint + '?failure=The requested resource does not exists!');
});

module.exports = router;