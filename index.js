"use strict";

var assert = require("assert");
var querystring = require("querystring");
var util = require("util");
var crypto = require("crypto");
var fs = require("fs");
var debug = require("debug")("wls");
var passport = require("passport");

var RESPONSE_PARTS = [
  "ver",
  "status",
  "msg",
  "issue",
  "id",
  "url",
  "principal",
  "ptags",
  "auth",
  "sso",
  "life",
  "params",
  "kid",
  "sig",
];

var ERROR_CODES = {
  410: "Raven authentication was cancelled by the user.",
  510: "No mutually acceptable authentication types available.",
  520: "Unsupported Raven WAA2WLS protocol version.",
  530: "Raven authentication failed due to error in request.",
  540: "Interaction would be required.",
  560: "WAA not authorised to authenticate with Raven.",
  570: "Raven authentication was declined on this occassion.",
};

exports = module.exports = Strategy;
exports.Strategy = Strategy;

function Strategy(options, verify) {
  if (typeof options.audience !== "string")
    throw new Error("You must provide an audience option.");
  if (typeof verify !== "function")
    throw new Error("You must provide a verify function.");
  this.name = options.name ? "wls-" + options.name : "wls";
  this._verify = verify;
  this._opts = options;

  this.clockOffset = options.clockOffset || 0;
  this.clockMargin = options.clockMargin || 60000;

  this.authUri =
    options.authUri || "https://raven.cam.ac.uk/auth/authenticate.html";
  this.keyId = options.keyId || "2";
  var keyPath = options.keyPath || __dirname + "/pubkey2.crt";
  this.key = fs.readFileSync(keyPath);
}
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function (req) {
  if (req.query["WLS-Response"]) {
    return this.processResponse(req);
  } else {
    return this.redirectToAuthenticate(req);
  }
};

Strategy.prototype.redirectToAuthenticate = function (req) {
  let prefix = "";
  if (req.mappedHost) {
    prefix = req.mappedHost;
  }
  var params = querystring.stringify({
    ver: 3,
    url:
      this._opts.audience + req.url + prefix
        ? "&host=" + encodeURIComponent(prefix)
        : "", //host=prefix,
    desc: this._opts.desc,
    msg: this._opts.msg,
    iact:
      this._opts.iact === true
        ? "yes"
        : this._opts.iact === false
        ? "no"
        : null,
  });
  this.redirect(this.authUri + "?" + params);
};

Strategy.prototype.processResponse = function (req) {
  var self = this;

  var response = decodeResponse(req);

  if (response.status !== "200") {
    var message =
      ERROR_CODES[response.status] ||
      "Raven authentication failed with unknown status " +
        response.status +
        ".";
    debug(message);
    if (response.status === "410") return this.fail();
    else return this.error(new Error(message));
  } else if (response.status === "200") {
    var interval = now() + this.clockOffset - parseDate(response.issue);
    if (interval < 0) interval = -interval;

    if (interval < this.clockMargin) {
      debug("Checking certificate.");
      //data = parameters - (sig + kid)
      var data = req.query["WLS-Response"].split("!").slice(0, -2).join("!");
      if (response.kid !== this.keyId) {
        debug(
          "WLS response using unknown key " +
            response.kid +
            ", expecting " +
            this.keyId
        );
        return this.error(
          new Error(
            "WLS response using unknown key " +
              response.kid +
              ", expecting " +
              this.keyId
          )
        );
      }
      if (checkSignature(data, response.sig, this.key)) {
        debug("WLS response signature check passed.");
        response.isCurrent = response.ptags === "current";
        if (self._opts["passReqToCallback"]) {
          return self._verify(
            req,
            response.principal,
            response,
            function (err, user, info) {
              if (err) {
                return self.error(err);
              }
              if (!user) {
                return self.fail(info);
              }
              self.success(user, info);
            }
          );
        } else {
          return self._verify(
            response.principal,
            response,
            function (err, user, info) {
              if (err) {
                return self.error(err);
              }
              if (!user) {
                return self.fail(info);
              }
              self.success(user, info);
            }
          );
        }
      } else {
        debug("WLS response signature check failed.");
        return this.error(new Error("WLS response signature check failed."));
      }
    } else {
      debug("Timestamp out of date.");
      return this.error(new Error("Timestamp out of date."));
    }
  }
};

function decodeResponse(req) {
  var values = req.query["WLS-Response"].split("!");
  if (
    values.length >= 1 &&
    ["1", "2"].indexOf(values[RESPONSE_PARTS.indexOf("ver")]) !== -1
  ) {
    // The response could have any version up to the one we specified in the request
    // In versions 1 and 2 of the protocol, there is no ptags response parameter, so we add an empty value to avoid any index issues
    values.splice(RESPONSE_PARTS.indexOf("ptags"), 0, "");
  }
  if (values.length !== RESPONSE_PARTS.length) {
    debug("Incorrect length of WLS-Response.");
    throw new Error("Incorrect length of WLS-Response.");
  }
  var response = {};
  values.forEach(function (item, i) {
    response[RESPONSE_PARTS[i]] = item;
  });
  return response;
}

function checkSignature(data, sig, key) {
  data = decodeURI(data);
  sig = wlsDecode(decodeURI(sig));
  var verifier = crypto.createVerify("SHA1");
  verifier.update(data);
  var res = verifier.verify(key, sig, "base64");
  if (res) {
    debug("Verification passed.");
    return true;
  } else {
    debug("Verification failed.");
    return false;
  }
}

function wlsDecode(str) {
  return str.replace(/-/g, "+").replace(/\./g, "/").replace(/_/g, "=");
}

function parseDate(str) {
  var match = /^(\d\d\d\d)(\d\d)(\d\d)T(\d\d)(\d\d)(\d\d)Z$/.exec(str);
  return Date.UTC(
    match[1],
    +match[2] - 1,
    match[3],
    match[4],
    match[5],
    match[6]
  );
}
function now() {
  return Date.now();
}
