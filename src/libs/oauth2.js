(function(root) {
  'use strict';

  var Oauth2 = function(scheme, credentials ,settings) {
    this.scheme = scheme;
    this.credentials = credentials;
    this.settings = settings;
  };

  function getScopes(credentials) {
    var scopes = [];

    if (credentials.scopes) {
      scopes = Object.keys(credentials.scopes).filter(function (scope) {
        return credentials.scopes[scope] === true;
      });
    }

    return scopes;
  }

  function popup(location) {
    var w    = 640;
    var h    = 480;
    var left = (screen.width / 2) - (w / 2);
    var top  = (screen.height / 2) - (h / 2);
    return window.open(location, 'Authentication', 'toolbar=no, location=no, directories=no, status=no, menubar=no, scrollbars=no, resizable=no, copyhistory=no, width=' + w + ', height=' + h + ', top=' + top + ', left=' + left);
  }

  Oauth2.prototype.authenticate = function(options, done) {
    var auth = new ClientOAuth2({
      clientId:         this.credentials.clientId,
      clientSecret:     this.credentials.clientSecret,
      accessTokenUri:   this.settings.accessTokenUri,
      authorizationUri: this.settings.authorizationUri,
      redirectUri:      this.settings.redirectUri,
      scopes:           getScopes(this.credentials),
      //MOD: mmontes - it needs for compass matching process
      actionParams:            this.settings.actionParams,
      third_party_user_id:  this.settings.third_party_user_id
    });

    var grantType = this.credentials.grant;
    var data = {},token={};
    // three legged
    if (grantType === 'token' || grantType === 'code' || grantType === 'authorization_code' || grantType === 'implicit') {
      window.oauth2Callback = function (uri) {
        auth[grantType].getToken(uri, function (err, user, raw) {
          if (err) {
            done(raw, err, {});
          }

          if (user && user.accessToken) {
            token = { 'tokenType': user.tokenType , 'accessToken' : user.accessToken };
            data['token'] = token;
            user.request(options, function (err, res) {
              done(res, err, data);
            });
          }
        });
      };
      var winAuth = popup(auth[grantType].getUri());
      winAuth.window.focus();
    }

    if (grantType === 'credentials'|| grantType === 'client_credentials') {
      auth.credentials.getToken(function (err, user, raw) {
        if (err) {
          done(raw, err, {});
        }
        if (user && user.accessToken) {
          token = { 'tokenType': user.tokenType , 'accessToken' : user.accessToken };
          data['token'] = token;
          user.request(options, function (err, res) {
            done(res, err, data);
          });
        }
      });
    }
  };

   /**
   * Export the OAuth2 client for multiple environments.
   */
  if (typeof define === 'function' && define.amd) {
    define([], function () {
      return Oauth2;
    });
  } else if (typeof exports === 'object') {
    module.exports = Oauth2;
  } else {
    root.Oauth2 = Oauth2;
  }
})(this);