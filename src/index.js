'use strict';
const { createActivationObserver } = require('./observer');
const { makeStore, createLicenseSecretVerifier, verifyLicenseSecret } = require('./store');
module.exports = { createActivationObserver, makeStore, createLicenseSecretVerifier, verifyLicenseSecret };
