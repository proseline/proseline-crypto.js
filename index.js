var assert = require('nanoassert')
var sodium = require('sodium-universal')
var stringify = require('fast-json-stable-stringify')

var DEFAULT_ENCODING = 'hex'
var DIGEST_ENCODING = exports.digestEncoding = DEFAULT_ENCODING
var KEY_ENCODING = exports.keyEncoding = DEFAULT_ENCODING
var NONCE_ENCODING = exports.nonceEncoding = DEFAULT_ENCODING
var RANDOM_ENCODING = exports.randomEncoding = DEFAULT_ENCODING
var SEED_ENCODING = exports.seedEncoding = DEFAULT_ENCODING
var SIGNATURE_ENCODING = exports.signatureEncoding = DEFAULT_ENCODING

var CIPHERTEXT_ENCODING = 'base64'

exports.ciphertextEncoding = CIPHERTEXT_ENCODING

var PLAINTEXT_ENCODING = 'utf8'

exports.plaintextEncoding = PLAINTEXT_ENCODING

// Random Data
// ===========

function random (bytes) {
  assert(Number.isInteger(bytes))
  assert(bytes > 0)
  var buffer = Buffer.alloc(bytes)
  sodium.randombytes_buf(buffer)
  return buffer.toString(RANDOM_ENCODING)
}

exports.random = random

// Hashing
// =======

var DIGEST_BYTES = sodium.crypto_generichash_BYTES

exports.digestBytes = DIGEST_BYTES

function hash (input) {
  assert(typeof input === 'string')
  var digestBuffer = Buffer.alloc(DIGEST_BYTES)
  sodium.crypto_generichash(digestBuffer, Buffer.from(input))
  return digestBuffer.toString(DIGEST_ENCODING)
}

exports.hash = hash

// Secret-Key Cryptography
// =======================

// Stream Encryption
// -----------------

var STREAM_KEY_BYTES = sodium.crypto_stream_KEYBYTES

exports.projectReplicationKey = function () {
  return random(STREAM_KEY_BYTES)
}

exports.projectReplicationKeyBytes = STREAM_KEY_BYTES

exports.discoveryKey = function (projectReplicationKey) {
  assert(typeof projectReplicationKey === 'string')
  assert(projectReplicationKey.length === STREAM_KEY_BYTES * 2)
  return hash(projectReplicationKey)
}

exports.discoveryKeyLength = DIGEST_BYTES

// Box Encryption
// --------------

var SECRETBOX_KEY_BYTES = sodium.crypto_secretbox_KEYBYTES

exports.projectReadKey = function () {
  return random(SECRETBOX_KEY_BYTES)
}

exports.projectReadKeyBytes = SECRETBOX_KEY_BYTES

var SECRETBOX_NONCE_BYTES = sodium.crypto_secretbox_NONCEBYTES

exports.randomNonce = function () {
  return random(SECRETBOX_NONCE_BYTES)
}

exports.nonceBytes = SECRETBOX_NONCE_BYTES

var SECRETBOX_MAC_BYTES = sodium.crypto_secretbox_MACBYTES

exports.encryptionMACBytes = SECRETBOX_MAC_BYTES

exports.encrypt = function (plaintext, nonce, key) {
  assert(typeof plaintext === 'string')
  assert(plaintext.length > 0)
  assert(typeof nonce === 'string')
  assert(nonce.length === SECRETBOX_NONCE_BYTES * 2)
  assert(typeof key === 'string')
  assert(key.length === SECRETBOX_KEY_BYTES * 2)
  var ciphertextBuffer = Buffer.alloc(plaintext.length + SECRETBOX_MAC_BYTES)
  sodium.crypto_secretbox_easy(
    ciphertextBuffer,
    Buffer.from(plaintext, PLAINTEXT_ENCODING),
    Buffer.from(nonce, NONCE_ENCODING),
    Buffer.from(key, KEY_ENCODING)
  )
  return ciphertextBuffer.toString(CIPHERTEXT_ENCODING)
}

exports.decrypt = function (ciphertext, nonce, key) {
  assert(typeof ciphertext === 'string')
  assert(ciphertext.length > 0)
  assert(typeof nonce === 'string')
  assert(nonce.length === SECRETBOX_NONCE_BYTES * 2)
  assert(typeof key === 'string')
  assert(key.length === SECRETBOX_KEY_BYTES * 2)
  var ciphertextBuffer = Buffer.from(ciphertext, CIPHERTEXT_ENCODING)
  var plaintextBuffer = Buffer.alloc(ciphertextBuffer.length - SECRETBOX_MAC_BYTES)
  var result = sodium.crypto_secretbox_open_easy(
    plaintextBuffer,
    ciphertextBuffer,
    Buffer.from(nonce, NONCE_ENCODING),
    Buffer.from(key, KEY_ENCODING)
  )
  if (!result) return false
  return plaintextBuffer.toString(PLAINTEXT_ENCODING)
}

// Public-Key Cryptography
// =======================

var SIGN_SEED_BYTES = sodium.crypto_sign_SEEDBYTES

exports.signingKeyPairSeedBytes = SIGN_SEED_BYTES

exports.signingKeyPairSeed = function () {
  return random(SIGN_SEED_BYTES)
}

var SIGN_PUBLIC_KEY_BYTES = sodium.crypto_sign_PUBLICKEYBYTES

exports.signingPublicKeyBytes = SIGN_PUBLIC_KEY_BYTES

var SIGN_SECRET_KEY_BYTES = sodium.crypto_sign_SECRETKEYBYTES

exports.signingSecretKeyBytes = SIGN_SECRET_KEY_BYTES

exports.signingKeyPairFromSeed = function (seed) {
  assert(typeof seed === 'string')
  assert(seed.length === SIGN_SEED_BYTES * 2)
  var publicKeyBuffer = Buffer.alloc(SIGN_PUBLIC_KEY_BYTES)
  var secretKeyBuffer = Buffer.alloc(SIGN_SECRET_KEY_BYTES)
  sodium.crypto_sign_seed_keypair(
    publicKeyBuffer,
    secretKeyBuffer,
    Buffer.from(seed, SEED_ENCODING)
  )
  return {
    secretKey: secretKeyBuffer.toString(KEY_ENCODING),
    publicKey: publicKeyBuffer.toString(KEY_ENCODING)
  }
}

exports.signingKeyPair = function () {
  var publicKeyBuffer = Buffer.alloc(SIGN_PUBLIC_KEY_BYTES)
  var secretKeyBuffer = Buffer.alloc(SIGN_SECRET_KEY_BYTES)
  sodium.crypto_sign_keypair(publicKeyBuffer, secretKeyBuffer)
  return {
    publicKey: publicKeyBuffer.toString(KEY_ENCODING),
    secretKey: secretKeyBuffer.toString(KEY_ENCODING)
  }
}

var SIGNATURE_BYTES = sodium.crypto_sign_BYTES

exports.signatureBytes = SIGNATURE_BYTES

exports.sign = function (object, secretKey, key) {
  assert(typeof object === 'object')
  assert(object.hasOwnProperty('entry'))
  assert(typeof secretKey === 'string')
  assert(secretKey.length === SIGN_SECRET_KEY_BYTES * 2)
  assert(typeof key === 'string')
  assert(key.length > 0)
  var signatureBuffer = Buffer.alloc(SIGNATURE_BYTES)
  sodium.crypto_sign_detached(
    signatureBuffer,
    Buffer.from(stringify(object.entry), 'utf8'),
    Buffer.from(secretKey, KEY_ENCODING)
  )
  object[key] = signatureBuffer.toString(SIGNATURE_ENCODING)
  return true
}

exports.verify = function (object, publicKey, signatureKey) {
  assert(typeof object === 'object')
  assert(object.hasOwnProperty('entry'))
  assert(typeof publicKey === 'string')
  assert(publicKey.length === SIGN_PUBLIC_KEY_BYTES * 2)
  assert(typeof signatureKey === 'string')
  assert(signatureKey.length > 0)
  assert(object.hasOwnProperty(signatureKey))
  assert(typeof object[signatureKey] === 'string')
  assert(object[signatureKey].length > 0)
  var signature = object[signatureKey]
  return sodium.crypto_sign_verify_detached(
    Buffer.from(signature, SIGNATURE_ENCODING),
    Buffer.from(stringify(object.entry), 'utf8'),
    Buffer.from(publicKey, KEY_ENCODING)
  )
}
