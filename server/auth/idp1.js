var passport = require('passport');
var SamlStrategy = require('passport-saml').Strategy;
var fs = require('fs');
var logger = require("../utils/logger");

var setCredentials = function(credentials) {
    var callbackURL = global.applicationHost.concat("/passport/auth/idp1/callback");

    var strategyConfigOptions = {
            callbackUrl: callbackURL,
            entryPoint: 'https://rk.local/idp/profile/SAML2/Redirect/SSO',
            issuer: 'urn:rksharma',
            decryptionPvk: fs.readFileSync(__dirname +'/minnow.pem', 'utf-8'),
            identifierFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
            cert: 'MIIDjDCCAnQCCQCY1owlKl9eejANBgkqhkiG9w0BAQsFADCBhzELMAkGA1UEBhMC SU4xDzANBgNVBAgMBlB1bmphYjEPMA0GA1UEBwwGTW9oYWxpMQ0wCwYDVQQKDARH bHV1MR4wHAYDVQQDDBVnbHV1LmVuZXRkZWZlbmRlci5jb20xJzAlBgkqhkiG9w0B CQEWGHN1cHBvcnRAZW5ldGRlZmVuZGVyLmNvbTAeFw0xNzA5MjkwNjU5MjBaFw0x ODA5MjkwNjU5MjBaMIGHMQswCQYDVQQGEwJJTjEPMA0GA1UECAwGUHVuamFiMQ8w DQYDVQQHDAZNb2hhbGkxDTALBgNVBAoMBEdsdXUxHjAcBgNVBAMMFWdsdXUuZW5l dGRlZmVuZGVyLmNvbTEnMCUGCSqGSIb3DQEJARYYc3VwcG9ydEBlbmV0ZGVmZW5k ZXIuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4Oqns6Vmxm7u A1r1TDde1BLsE2Khmn6g2QFx24TH+nwlrTaAbQumnJhUn/6/9+PgHMQxmUeCjbqv E3Gvg9e5OXL4MAZWcH5SnWR780wUqvu/jsxZz1TtEGmIigGqABqsmqENPkCV2SZI RzoJWNg+hAYNOM9WdlS6lJbc3FSdm7nQMCEaLD65zieCmMt+I/3P/uqStH2I1Y6h 9E3SdUz/ZL3b5Zlhkgn0lipDfPLdr3rk9oIcdNYhLwsoB4D0VWt0j12ZqPA7N3gG 6gr9/sf31dZz3HQFlfeaLOXuyFV1oABssiKmctT2UnZDbDzf2vYhHfYUym7b4DBg 8dluTB3BswIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBXpdLApn+91EIuPLPhePLW JBYJ8sPDeUP+BZbqLWnj761D+nTn+obDtDkFFyVHzIuSpubhGWT9q/QZby25PAK1 uWmIAL0ABYb1unw+j/nWmjCQv51vLDPNrW5jTCJS8WwpfoXH4rvYibkMHQOwALVM AJg+luBG1hcEhp94qDevcDu8dDkee5qIRzmNFfXrHyXysZc+qqTRTXN3pSD8+6LL COg2X9Kx2viAgoYWlrTQis+PiTtSQtiaI/4OFl1ShrUa1Rz0V/vanmKXaMyHYRWp stGJTH0x2Hu89FRjMlni+TSgzuxhLiMZMFaUnwGT4KTt+HoeYwEIEweJU+yrzRIG'
        };
    var strategy = new SamlStrategy(strategyConfigOptions,
        function(accessToken, refreshToken, profile, done) {
            logger.log('info', profile);

    //        var entitiesJSON = JSON.parse(fs.readFileSync('entities.json', 'utf8'));

    //        if(entitiesJSON.hasOwnProperty(strategyConfigOptions.issuer) {
                var userProfile = {
                    id: profile.uid,
                    email: profile.email,
                    accessToken : accessToken
                 };
                 return done(null, userProfile);

    //        }else{
    //            console.error("IDP Entity not Found.")
     //           return false;
     //       }
        }
    );
    passport.use(strategy);
    if (!fs.open(__dirname +'/FederationMetadata.xml','r',function(err, fd) {
          if (err) {
                return console.error(err);
          }
    }
    console.log("File opened successfully!");
   })) {
   var decryptionCert = fs.readFileSync(__dirname + '/minnow_pub.pem', 'utf-8');
   var metaData = strategy.generateServiceProviderMetadata(decryptionCert);
   fs.writeFile(__dirname +'/FederationMetadata.xml', metaData, function(err) {
           if (err) {
                   return console.error(err);
           }
           console.log("Data written successfully!");
   });}
};

module.exports = {
passport: passport,
setCredentials: setCredentials
};