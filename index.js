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
  var key = Buffer.alloc(STREAM_KEY_BYTES)
  sodium.crypto_secretstream_xchacha20poly1305_keygen(key)
  return key
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

var BOX_SECRET_KEY_BYTES = sodium.crypto_box_SECRETKEYBYTES

exports.makeProjectReadKey = function () {
  return randomBuffer(BOX_SECRET_KEY_BYTES)
}

exports.projectReadKeyBytes = BOX_SECRET_KEY_BYTES

var BOX_NONCE_BYTES = sodium.crypto_secretbox_NONCEBYTES

exports.randomNonce = function () {
  return randomBuffer(BOX_NONCE_BYTES)
}

exports.nonceBytes = BOX_NONCE_BYTES

var BOX_MAC_BYTES = sodium.crypto_secretbox_MACBYTES

exports.encryptionMACBytes = BOX_MAC_BYTES

exports.encrypt = function (plaintext, nonce, key) {
  assert(Buffer.isBuffer(plaintext))
  assert(plaintext.length > 0)
  assert(Buffer.isBuffer(nonce))
  assert(nonce.length === BOX_NONCE_BYTES)
  assert(Buffer.isBuffer(key))
  assert(key.length === BOX_SECRET_KEY_BYTES)
  var ciphertext = Buffer.alloc(plaintext.length + BOX_MAC_BYTES)
  sodium.crypto_secretbox_easy(ciphertext, plaintext, nonce, key)
  return ciphertext
}

exports.decrypt = function (ciphertext, nonce, key) {
  assert(Buffer.isBuffer(ciphertext))
  assert(ciphertext.length > 0)
  assert(Buffer.isBuffer(nonce))
  assert(nonce.length === BOX_NONCE_BYTES)
  assert(Buffer.isBuffer(key))
  assert(key.length === BOX_SECRET_KEY_BYTES)
  var plaintext = Buffer.alloc(ciphertext.length + BOX_MAC_BYTES)
  var result = sodium.crypto_secretbox_open_easy(
    plaintext, ciphertext, nonce, key
  )
  if (!result) return false
  return plaintext
}

// Public-Key Cryptography
// =======================

var SIGN_SEED_BYTES = sodium.crypto_sign_SEEDBYTES

exports.makeSigningKeyPairSeed = function () {
  var seed = Buffer.alloc(SIGN_SEED_BYTES)
  sodium.randombytes_buf(seed)
  return seed
}

exports.signingKeyPairSeedBytes = SIGN_SEED_BYTES

var SIGN_PUBLIC_KEY_BYTES = sodium.crypto_sign_PUBLICKEYBYTES

var SIGN_SECRET_KEY_BYTES = sodium.crypto_sign_SECRETKEYBYTES

exports.makeSigningKeyPair = function () {
  var publicKey = Buffer.alloc(SIGN_PUBLIC_KEY_BYTES)
  var secretKey = Buffer.alloc(SIGN_SECRET_KEY_BYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return {
    publicKey: publicKey,
    secretKey: secretKey
  }
}

exports.signingPublicKeyBytes = SIGN_PUBLIC_KEY_BYTES

exports.signingSecretKeyBytes = SIGN_SECRET_KEY_BYTES

var SIGNATURE_BYTES = sodium.crypto_sign_BYTES

exports.sign = function (object, keyPair, key) {
  assert(typeof object === 'object')
  assert(object.hasOwnProperty('entry'))
  assert(typeof keyPair === 'object')
  assert(keyPair.hasOwnProperty('secretKey'))
  assert(typeof key === 'string')
  assert(key.length > 0)
  var signature = Buffer.alloc(SIGNATURE_BYTES)
  sodium.crypto_sign_detached(
    signature,
    Buffer.from(stringify(object.entry), 'utf8'),
    keyPair.secretKey
  )
  object[key] = signature.toString('hex')
}

exports.signatureBytes = SIGNATURE_BYTES
