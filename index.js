var assert = require('nanoassert')
var sodium = require('sodium-universal')
var stringify = require('fast-json-stable-stringify')

var BINARY_ENCODING = 'base64'

exports.binaryEncoding = BINARY_ENCODING

// Random Data

function random (bytes) {
  assert(Number.isInteger(bytes))
  assert(bytes > 0)
  var buffer = Buffer.alloc(bytes)
  sodium.randombytes_buf(buffer)
  return buffer.toString(BINARY_ENCODING)
}

exports.random = random

// Hashing

var DIGEST_BYTES = sodium.crypto_generichash_BYTES

exports.digestBytes = DIGEST_BYTES

function hash (input) {
  assert(typeof input === 'string')
  var digestBuffer = Buffer.alloc(DIGEST_BYTES)
  sodium.crypto_generichash(digestBuffer, Buffer.from(input))
  return digestBuffer.toString(BINARY_ENCODING)
}

exports.hash = hash

// Stream Encryption

var STREAM_KEY_BYTES = sodium.crypto_stream_KEYBYTES

exports.replicationKey = function () {
  return random(STREAM_KEY_BYTES)
}

exports.replicationKeyBytes = STREAM_KEY_BYTES

exports.discoveryKey = function (replicationKey) {
  assert(typeof replicationKey === 'string')
  return hash(replicationKey)
}

exports.discoveryKeyLength = DIGEST_BYTES

// Box Encryption

var SECRETBOX_KEY_BYTES = sodium.crypto_secretbox_KEYBYTES

exports.encryptionKey = function () {
  return random(SECRETBOX_KEY_BYTES)
}

exports.encryptionKeyBytes = SECRETBOX_KEY_BYTES

var SECRETBOX_NONCE_BYTES = sodium.crypto_secretbox_NONCEBYTES

exports.nonce = function () {
  return random(SECRETBOX_NONCE_BYTES)
}

exports.nonceBytes = SECRETBOX_NONCE_BYTES

var SECRETBOX_MAC_BYTES = sodium.crypto_secretbox_MACBYTES

exports.encryptionMACBytes = SECRETBOX_MAC_BYTES

var inputTypes = {
  JSON: 'json',
  String: 'utf8',
  Binary: 'base64'
}

Object.keys(inputTypes).forEach(function (suffix) {
  var encoding = inputTypes[suffix]
  exports['encrypt' + suffix] = function (plaintext, nonce, key) {
    return encrypt(plaintext, encoding, nonce, key)
  }
  exports['decrypt' + suffix] = function (ciphertext, nonce, key) {
    return decrypt(ciphertext, encoding, nonce, key)
  }
})

function encrypt (plaintext, encoding, nonce, key) {
  var plaintextBuffer = decode(plaintext, encoding)
  var ciphertextBuffer = Buffer.alloc(
    plaintextBuffer.length + SECRETBOX_MAC_BYTES
  )
  sodium.crypto_secretbox_easy(
    ciphertextBuffer,
    plaintextBuffer,
    Buffer.from(nonce, BINARY_ENCODING),
    Buffer.from(key, BINARY_ENCODING)
  )
  return ciphertextBuffer.toString(BINARY_ENCODING)
}

function decrypt (ciphertext, encoding, nonce, key) {
  var ciphertextBuffer = decode(ciphertext, BINARY_ENCODING)
  var plaintextBuffer = Buffer.alloc(
    ciphertextBuffer.length - SECRETBOX_MAC_BYTES
  )
  var result = sodium.crypto_secretbox_open_easy(
    plaintextBuffer,
    ciphertextBuffer,
    Buffer.from(nonce, BINARY_ENCODING),
    Buffer.from(key, BINARY_ENCODING)
  )
  if (!result) return false
  return encode(plaintextBuffer, encoding)
}

// Signature

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
  var publicKeyBuffer = Buffer.alloc(SIGN_PUBLIC_KEY_BYTES)
  var secretKeyBuffer = Buffer.alloc(SIGN_SECRET_KEY_BYTES)
  sodium.crypto_sign_seed_keypair(
    publicKeyBuffer,
    secretKeyBuffer,
    Buffer.from(seed, BINARY_ENCODING)
  )
  return {
    secretKey: secretKeyBuffer.toString(BINARY_ENCODING),
    publicKey: publicKeyBuffer.toString(BINARY_ENCODING)
  }
}

exports.signingKeyPair = function () {
  var publicKeyBuffer = Buffer.alloc(SIGN_PUBLIC_KEY_BYTES)
  var secretKeyBuffer = Buffer.alloc(SIGN_SECRET_KEY_BYTES)
  sodium.crypto_sign_keypair(publicKeyBuffer, secretKeyBuffer)
  return {
    publicKey: publicKeyBuffer.toString(BINARY_ENCODING),
    secretKey: secretKeyBuffer.toString(BINARY_ENCODING)
  }
}

var SIGNATURE_BYTES = sodium.crypto_sign_BYTES

exports.signatureBytes = SIGNATURE_BYTES

Object.keys(inputTypes).forEach(function (suffix) {
  var encoding = inputTypes[suffix]
  exports['sign' + suffix] = function (object, secretKey) {
    return sign(object, encoding, secretKey)
  }
  exports['verify' + suffix] = function (message, signature, publicKey) {
    return verify(message, encoding, signature, publicKey)
  }
})

function sign (message, messageEncoding, secretKey) {
  assert(typeof secretKey === 'string')
  var signatureBuffer = Buffer.alloc(SIGNATURE_BYTES)
  sodium.crypto_sign_detached(
    signatureBuffer,
    decode(message, messageEncoding),
    Buffer.from(secretKey, BINARY_ENCODING)
  )
  return signatureBuffer.toString(BINARY_ENCODING)
}

function verify (message, encoding, signature, publicKey) {
  assert(typeof signature === 'string')
  assert(typeof publicKey === 'string')
  return sodium.crypto_sign_verify_detached(
    Buffer.from(signature, BINARY_ENCODING),
    decode(message, encoding),
    Buffer.from(publicKey, BINARY_ENCODING)
  )
}

function encode (buffer, encoding) {
  assert(Buffer.isBuffer(buffer))
  if (encoding === 'base64' || encoding === 'utf8') {
    return buffer.toString(encoding)
  }
  if (encoding === 'json') {
    return JSON.parse(buffer)
  }
  throw new Error('unsupported encoding: ' + encoding)
}

function decode (message, encoding) {
  assert(message !== undefined)
  if (encoding === 'base64' || encoding === 'utf8') {
    return Buffer.from(message, encoding)
  }
  if (encoding === 'json') {
    return Buffer.from(stringify(message), 'utf8')
  }
  throw new Error('unsupported encoding: ' + encoding)
}
