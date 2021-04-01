'use strict'

/**
 * Module dependencies.
 * @private
 */

var Cookie = require('cookie')
var showError = require('http-errors')
var sign = require('cookie-signature').sign
var Tokens = require('csrf')

/**
 * Module exports.
 * @public
 */

module.exports = csrfDefenseLibrary

/**
 * CSRF protection middleware.
 * To create a token, this middleware adds the req.csrfToken() function.
 * which should be added to requests that change state, such as form fields,
 * query strings, and so on. The validity of this token is checked it 
 * against user's session.
 *
 * @param {Object} headOptions
 * @return {Function} middleware
 * @public
 */

function csrfDefenseLibrary(headOptions) {

  //
  var optionsValue = headOptions || {}

  // console.log("OPTIONS ", optionsValue);
  // get cookie options

  var cookie = getHeadOptionsCookie(optionsValue.cookie)
  console.log("COOKIE", cookie)

  // get session options
  var sessionKeyValue = optionsValue.sessionKey || 'session'
  console.log("SessionKey", sessionKeyValue)

  // get value getter
  var value = optionsValue.value || defaultValue
  console.log("Value", value)

  // token for vlaue of options 
  var tokens = new Tokens(optionsValue)
  // console.log("Tokens", tokens);

  // ignored methods
  var ignoreMethods = optionsValue.ignoreMethods === undefined
    ? ['GET', 'HEAD', 'OPTIONS']
    : optionsValue.ignoreMethods

  if (!Array.isArray(ignoreMethods)) {
    throw new TypeError('option ignoreMethods must be an array')
  }

  // generate lookup
  var ignoreMethod = getIgnoredMethods(ignoreMethods)

  return function csrf(req, res, next) {

    // console.log("CSRF-signed-cookie", req["signedCookies"]);
    // console.log("CSRF-cookie", req["cookies"]);

    // validate the configuration against request
    if (!verifyConfigurationData(req, sessionKeyValue, cookie)) {
      return next(new Error('misconfigured csrf'))
    }

    // get the secret from the request
    var secret = getSecretCookie(req, cookie)
    var token

      // lazy-load token getter
      req.csrfToken = function csrfToken () {
        var sec = !cookie
          ? getSecretCookie(req, cookie)
          : secret
  
        // generate & set new secret
        if (sec === undefined) {
          sec = tokens.secretSync()
          checkCookiePresent(req, res, sec, cookie)
        }
  
        // update changed secret
        secret = sec
  
        // create new token
        token = tokens.create(secret)
  
        return token
      }

    // generate & set secret
    if (!secret) {
      secret = tokens.secretSync()
      checkCookiePresent(req, res, secret, cookie)
    }

    console.log("SECRET", secret);
    console.log("Value", value);
    console.log("Value-Req", value(req));


    // verify and check if incoming tokens are valid tokens
    if (!ignoreMethod[req.method] && !tokens.verify(secret, value(req))) {

      return next(showError(403, 'Csrf Token not valid'))

    }

    next()
  }
}

function defaultValue(req) {
  return (req.body && req.body.csrf_secret) ||
    (req.query && req.query.csrf_secret) ||
    (req.headers['csrf-token']) ||
    (req.headers['xsrf-token']) ||
    (req.headers['x-csrf-token']) ||
    (req.headers['x-xsrf-token'])
}

/*
 Get options for cookie.
*/

function getHeadOptionsCookie(headOptions) {
  if (headOptions !== true && typeof headOptions !== 'object') {
    return undefined
  }

  var optionsValue = Object.create(null)

  // defaults key and path
  optionsValue.key = 'csrf_secret'
  optionsValue.path = '/'

  if (headOptions && typeof headOptions === 'object') {
    for (var prop in headOptions) {
      var val = headOptions[prop]
      console.log("VAL", val);

      if (val !== undefined) {
        optionsValue[prop] = val
      }
    }
  }

  return optionsValue
}

function SetCookieSecret(res, name, val, headOptions) {
  var data = Cookie.serialize(name, val, headOptions)

  var prev = res.getHeader('set-cookie') || []
  var header = Array.isArray(prev) ? prev.concat(data)
    : [prev, data]

  res.setHeader('set-cookie', header)
}

function verifyConfigurationData(req, sessionKeyValue, cookie) {

  if (!req['cookies']) {
    return false
  }


  if (cookie && cookie.signed && !req.secret) {
    return false
  }

  return true
}

function getSecretCookie(req, cookie) {

  // get the bag & key
  var bag = req['cookies'];
  // console.log("BAG", bag);

  var key = cookie ? cookie.key : 'csrf_secret'
  // console.log("KEY", key);

  if (!bag) {
    throw new Error('csrf is missing')
  }
  // return secret from bag
  return bag[key]
}

function getIgnoredMethods(methods) {
  var obj = Object.create(null)

  for (var i = 0; i < methods.length; i++) {
    var method = methods[i].toUpperCase()
    obj[method] = true
  }

  return obj
}

function checkCookiePresent(req, res, val, cookie) {
  if (cookie) {
    // set secret on cookie
    var value = val

    SetCookieSecret(res, cookie.key, value, cookie)
  } 
  return false;
}

function SetCookieSecret(res, name, val, headOptions) {
  var data = Cookie.serialize(name, val, headOptions)

  var prev = res.getHeader('set-cookie') || []

  var header = Array.isArray(prev) ? prev.concat(data)
    : [prev, data]

  res.setHeader('set-cookie', header)
}
