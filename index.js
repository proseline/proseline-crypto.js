var assert = require('nanoassert')
var sodium = require('sodium-universal')
var stringify = require('fast-json-stable-stringify')

// Random Data
// ===========

function randomBuffer (bytes) {
  assert(Number.isInteger(bytes))
  assert(bytes > 0)
  var buffer = Buffer.alloc(bytes)
  sodium.randombytes_buf(buffer)
  return buffer
}

exports.randomBuffer = randomBuffer

// Hashing
// =======

var HASH_BYTES = sodium.crypto_generichash_BYTES

exports.hashBytes = HASH_BYTES

function hash (input) {
  assert(Buffer.isBuffer(input))
  var digest = Buffer.alloc(HASH_BYTES)
  sodium.crypto_generichash(digest, input)
  return digest
}

exports.hash = hash

// Secret-Key Cryptography
// =======================

// Stream Encryption
// -----------------

var STREAM_KEY_BYTES = sodium.crypto_stream_KEYBYTES

exports.makeProjectReplicationKey = function () {
  return randomBuffer(STREAM_KEY_BYTES)
}

exports.projectReplicationKeyBytes = STREAM_KEY_BYTES

exports.makeDiscoveryKey = function (projectReplicationKey) {
  assert(Buffer.isBuffer(projectReplicationKey))
  assert(projectReplicationKey.length === STREAM_KEY_BYTES)
  return hash(projectReplicationKey)
}

exports.discoveryKeyLength = HASH_BYTES

// Box Encryption
// --------------

var SECRETBOX_KEY_BYTES = sodium.crypto_secretbox_KEYBYTES

exports.makeProjectReadKey = function () {
  return randomBuffer(SECRETBOX_KEY_BYTES)
}

exports.projectReadKeyBytes = SECRETBOX_KEY_BYTES

var SECRETBOX_NONCE_BYTES = sodium.crypto_secretbox_NONCEBYTES

exports.randomNonce = function () {
  return randomBuffer(SECRETBOX_NONCE_BYTES)
}

exports.nonceBytes = SECRETBOX_NONCE_BYTES

var SECRETBOX_MAC_BYTES = sodium.crypto_secretbox_MACBYTES

exports.encryptionMACBytes = SECRETBOX_MAC_BYTES

exports.encrypt = function (plaintext, nonce, key) {
  assert(Buffer.isBuffer(plaintext))
  assert(plaintext.length > 0)
  assert(Buffer.isBuffer(nonce))
  assert(nonce.length === SECRETBOX_NONCE_BYTES)
  assert(Buffer.isBuffer(key))
  assert(key.length === SECRETBOX_KEY_BYTES)
  var ciphertext = Buffer.alloc(plaintext.length + SECRETBOX_MAC_BYTES)
  sodium.crypto_secretbox_easy(ciphertext, plaintext, nonce, key)
  return ciphertext
}

exports.decrypt = function (ciphertext, nonce, key) {
  assert(Buffer.isBuffer(ciphertext))
  assert(ciphertext.length > 0)
  assert(Buffer.isBuffer(nonce))
  assert(nonce.length === SECRETBOX_NONCE_BYTES)
  assert(Buffer.isBuffer(key))
  assert(key.length === SECRETBOX_KEY_BYTES)
  var plaintext = Buffer.alloc(ciphertext.length - SECRETBOX_MAC_BYTES)
  var result = sodium.crypto_secretbox_open_easy(
    plaintext, ciphertext, nonce, key
  )
  if (!result) return false
  return plaintext
}

// Public-Key Cryptography
// =======================

var SIGN_SEED_BYTES = sodium.crypto_sign_SEEDBYTES

exports.signingKeyPairSeedBytes = SIGN_SEED_BYTES

exports.makeSigningKeyPairSeed = function () {
  var seed = Buffer.alloc(SIGN_SEED_BYTES)
  sodium.randombytes_buf(seed)
  return seed
}

var SIGN_PUBLIC_KEY_BYTES = sodium.crypto_sign_PUBLICKEYBYTES

exports.signingPublicKeyBytes = SIGN_PUBLIC_KEY_BYTES

var SIGN_SECRET_KEY_BYTES = sodium.crypto_sign_SECRETKEYBYTES

exports.signingSecretKeyBytes = SIGN_SECRET_KEY_BYTES

exports.makeSigningKeyPairFromSeed = function (seed) {
  assert(Buffer.isBuffer(seed))
  assert(seed.length === SIGN_SEED_BYTES)
  var publicKey = Buffer.alloc(SIGN_PUBLIC_KEY_BYTES)
  var secretKey = Buffer.alloc(SIGN_SECRET_KEY_BYTES)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, seed)
  return {
    secretKey: secretKey,
    publicKey: publicKey
  }
}

exports.makeSigningKeyPair = function () {
  var publicKey = Buffer.alloc(SIGN_PUBLIC_KEY_BYTES)
  var secretKey = Buffer.alloc(SIGN_SECRET_KEY_BYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return {
    publicKey: publicKey,
    secretKey: secretKey
  }
}

var SIGNATURE_BYTES = sodium.crypto_sign_BYTES

exports.sign = function (object, secretKey, key) {
  assert(typeof object === 'object')
  assert(object.hasOwnProperty('entry'))
  assert(Buffer.isBuffer(secretKey))
  assert(secretKey.length === SIGN_SECRET_KEY_BYTES)
  assert(typeof key === 'string')
  assert(key.length > 0)
  var signature = Buffer.alloc(SIGNATURE_BYTES)
  sodium.crypto_sign_detached(
    signature,
    Buffer.from(stringify(object.entry), 'utf8'),
    secretKey
  )
  object[key] = signature.toString('hex')
}

exports.signatureBytes = SIGNATURE_BYTES
