"use strict";


/********* External Imports ********/

var lib = require("./lib");

var KDF = lib.KDF,
    HMAC = lib.HMAC,
    SHA256 = lib.SHA256,
    setupCipher = lib.setupCipher,
    encryptwithGCM = lib.encryptwithGCM,
    decryptWithGCM = lib.decryptWithGCM,
    bitarraySlice = lib.bitarraySlice,
    bitarrayToString = lib.bitarrayToString,
    stringToBitarray = lib.stringToBitarray,
    bitarrayToBase64 = lib.bitarrayToBase64,
    base64ToBitarray = lib.base64ToBitarray,
    stringToPaddedBitarray = lib.stringToPaddedBitarray,
    paddedBitarrayToString = lib.paddedBitarrayToString,
    randomBitarray = lib.randomBitarray,
    bitarrayEqual = lib.bitarrayEqual,
    bitarrayLen = lib.bitarrayLen,
    bitarrayConcat = lib.bitarrayConcat,
    objectHasKey = lib.objectHasKey;


/********* Implementation ********/


var keychainClass = function() {

  // Private instance variables.
    
  // Use this variable to store everything you need to.
  var priv = {
    secrets: {},
    data: { 'salt': {}, 'entryCheck': {} }
  };

  // Maximum length of each record in bytes
  var MAX_PW_LEN_BYTES = 64;
  
  // Flag to indicate whether password manager is "ready" or not
  var ready = false;

  var keychain = {};

  /** 
    * Creates an empty keychain with the given password. Once init is called,
    * the password manager should be in a ready state.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  keychain.init = function(password) {
    // set public data
    priv.data.version = "CS 255 Password Manager v1.0";
    priv.data.salt.master = randomBitarray(64);
    priv.data.salt.HMAC = randomBitarray(64);
    priv.data.salt.AES_GCM = randomBitarray(64);
    priv.data.salt.entryCheck = randomBitarray(64);
    priv.data.salt.passwordCheck = randomBitarray(64);
    // derive keys for HMAC and AES-GCM + create password check
    var masterKey = KDF(password, priv.data.salt.master);
    priv.secrets.HMAC = HMAC(masterKey, priv.data.salt.HMAC);
    priv.secrets.AES_GCM = bitarraySlice(HMAC(masterKey, priv.data.salt.AES_GCM), 0, 128);
    priv.secrets.entryCheck = HMAC(masterKey, priv.data.salt.entryCheck);
    priv.data.passwordCheck = HMAC(masterKey, priv.data.salt.passwordCheck);
    // initialize the keychain + KVS
    keychain['kvs'] = {};
    ready = true;
  };

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the save function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object). Returns true if the data is successfully loaded
    * and the provided password is correct. Returns false otherwise.
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: boolean
    */
  keychain.load = function(password, repr, trustedDataCheck) {
    if (trustedDataCheck !== undefined) {
      var hashedDump = SHA256(stringToBitarray(repr));
      if (!bitarrayEqual(hashedDump, trustedDataCheck)) throw "Keychain integrity check failed!"
    }
    // parse the serialized content
    var objToLoad = JSON.parse(repr);
    keychain['kvs'] = objToLoad['kvs'];
    priv.data = objToLoad['data'];
    // derive keys for HMAC and AES-GCM
    var masterKey = KDF(password, priv.data.salt.master);
    priv.secrets.HMAC = HMAC(masterKey, priv.data.salt.HMAC);
    priv.secrets.AES_GCM = bitarraySlice(HMAC(masterKey, priv.data.salt.AES_GCM), 0, 128);
    priv.secrets.entryCheck = HMAC(masterKey, priv.data.salt.entryCheck);
    // check password correctness
    var passwordCheck = HMAC(masterKey, priv.data.salt.passwordCheck);
    ready = bitarrayEqual(priv.data.passwordCheck, passwordCheck);
    return ready;
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity. If the
    * password manager is not in a ready-state, return null.
    *
    * Return Type: array
    */ 
  keychain.dump = function() {
    if (!ready) return null;
    var objToDump = {'kvs': keychain['kvs'], 'data': priv.data}
    var serializedDump = JSON.stringify(objToDump);
    var hashedDump = SHA256(stringToBitarray(serializedDump));
    return [serializedDump, hashedDump]
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null. If the password manager is not in a ready state, throw an exception. If
    * tampering has been detected with the records, throw an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: string
    */
  keychain.get = function(name) {
    if (!ready) throw "Keychain not initialized.";
    // check if encoded domain exists
    var domainHMAC = HMAC(priv.secrets.HMAC, name);
    var domain = bitarrayToBase64(domainHMAC);
    if (!objectHasKey(keychain['kvs'], domain)) return null;
    // decrypt password
    var encryptedPassword = keychain['kvs'][domain];
    var cipher = setupCipher(priv.secrets.AES_GCM);
    var paddedPassword = decryptWithGCM(cipher, encryptedPassword, priv.data.entryCheck[domain]);
    var password = paddedBitarrayToString(paddedPassword, MAX_PW_LEN_BYTES);
    // check KVS record against authenticated data
    var record = bitarrayConcat(domainHMAC, paddedPassword);
    var recordHMAC = HMAC(priv.secrets.entryCheck, record); 
    if (!bitarrayEqual(recordHMAC, priv.data.entryCheck[domain])) throw "Record integrity check failed!"
    return password;
  };

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager. If the password manager is
  * not in a ready state, throw an exception.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  keychain.set = function(name, value) {
    if (!ready) throw "Keychain not initialized.";
    // encode the domain + pad the password
    var domainHMAC = HMAC(priv.secrets.HMAC, name);
    var domain = bitarrayToBase64(domainHMAC);
    var paddedPassword = stringToPaddedBitarray(value, MAX_PW_LEN_BYTES);
    // create authenticated data to check the KVS record against
    var record = bitarrayConcat(domainHMAC, paddedPassword);
    priv.data.entryCheck[domain] = HMAC(priv.secrets.entryCheck, record);
    // encrypt password + add to KVS
    var cipher = setupCipher(priv.secrets.AES_GCM);
    var encryptedPassword = encryptwithGCM(cipher, paddedPassword, priv.data.entryCheck[domain]);
    keychain['kvs'][domain] = encryptedPassword;
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise. If
    * the password manager is not in a ready state, throws an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: boolean
  */
  keychain.remove = function(name) {
    if (!ready) throw "Keychain not initialized.";
    var domain = bitarrayToBase64(HMAC(priv.secrets.HMAC, name));
    if (objectHasKey(keychain['kvs'], domain)) return delete keychain['kvs'][domain];
    return false;
  };

  return keychain;
};

module.exports.keychain = keychainClass;
