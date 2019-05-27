var assert = require('nanoassert')
var sodium = require('sodium-universal')
var stringify = require('fast-json-stable-stringify')

var BINARY_ENCODING = exports.binaryEncoding = 'base64'

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

var DIGEST_BYTES = exports.digestBytes = sodium.crypto_generichash_BYTES

function hash (input) {
  assert(typeof input === 'string')
  var digestBuffer = Buffer.alloc(DIGEST_BYTES)
  sodium.crypto_generichash(digestBuffer, Buffer.from(input))
  return digestBuffer.toString(BINARY_ENCODING)
}

exports.hash = hash

// Stream Encryption

var STREAM_KEY_BYTES =
exports.replicationKeyBytes =
sodium.crypto_stream_KEYBYTES

exports.replicationKey = function () {
  return random(STREAM_KEY_BYTES)
}

exports.discoveryKey = function (replicationKey) {
  assert(typeof replicationKey === 'string')
  return hash(replicationKey)
}

exports.discoveryKeyLength = DIGEST_BYTES

// Box Encryption

var SECRETBOX_KEY_BYTES =
exports.encryptionKeyBytes =
sodium.crypto_secretbox_KEYBYTES

exports.encryptionKey = function () {
  return random(SECRETBOX_KEY_BYTES)
}

var SECRETBOX_NONCE_BYTES =
exports.nonceBytes =
sodium.crypto_secretbox_NONCEBYTES

exports.nonce = function () {
  return random(SECRETBOX_NONCE_BYTES)
}

var SECRETBOX_MAC_BYTES =
exports.encryptionMACBytes =
sodium.crypto_secretbox_MACBYTES

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

var SIGN_SEED_BYTES =
exports.keyPairSeedBytes =
sodium.crypto_sign_SEEDBYTES

exports.keyPairSeed = function () {
  return random(SIGN_SEED_BYTES)
}

var SIGN_PUBLIC_KEY_BYTES =
exports.publicKeyBytes =
sodium.crypto_sign_PUBLICKEYBYTES

var SIGN_SECRET_KEY_BYTES =
exports.secretKeyBytes =
sodium.crypto_sign_SECRETKEYBYTES

exports.keyPairFromSeed = function (seed) {
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

exports.keyPair = function () {
  var publicKeyBuffer = Buffer.alloc(SIGN_PUBLIC_KEY_BYTES)
  var secretKeyBuffer = Buffer.alloc(SIGN_SECRET_KEY_BYTES)
  sodium.crypto_sign_keypair(publicKeyBuffer, secretKeyBuffer)
  return {
    publicKey: publicKeyBuffer.toString(BINARY_ENCODING),
    secretKey: secretKeyBuffer.toString(BINARY_ENCODING)
  }
}

var SIGNATURE_BYTES =
exports.signatureBytes =
sodium.crypto_sign_BYTES

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

// Envelopes

exports.envelope = function (options) {
  assert(typeof options === 'object')
  var discoveryKey = options.discoveryKey
  assert(typeof discoveryKey === 'string')
  var entry = options.entry
  assert(typeof entry === 'object')
  var logKeyPair = options.logKeyPair
  assert(typeof logKeyPair === 'object')
  assert(typeof logKeyPair.publicKey === 'string')
  assert(typeof logKeyPair.secretKey === 'string')
  var projectKeyPair = options.projectKeyPair
  assert(typeof projectKeyPair === 'object')
  assert(typeof projectKeyPair.publicKey === 'string')
  assert(typeof projectKeyPair.secretKey === 'string')
  var encryptionKey = options.encryptionKey
  var index = options.index
  assert(Number.isSafeInteger(index))
  assert(index >= 0)
  var prior = options.prior
  if (index > 0) assert(typeof prior === 'string')

  entry.index = index
  if (index > 0) entry.prior = prior
  var nonce = exports.nonce()
  var ciphertext = exports.encryptJSON(entry, nonce, encryptionKey)
  var envelope = {
    discoveryKey: entry.discoveryKey,
    index: entry.index,
    prior: entry.prior,
    logPublicKey: logKeyPair.publicKey,
    logSignature: exports.signBinary(
      ciphertext, logKeyPair.secretKey
    ),
    projectSignature: exports.signBinary(
      ciphertext, projectKeyPair.secretKey
    ),
    entry: { ciphertext, nonce }
  }
  return envelope
}

exports.validateEnvelope = function (options) {
  var envelope = options.envelope
  assert(typeof envelope === 'object')
  var projectPublicKey = options.projectPublicKey
  assert(typeof projectPublicKey === 'string')
  var logPublicKey = options.logPublicKey
  assert(typeof logPublicKey === 'string')
  var encryptionKey = options.encryptionKey
  assert(typeof encryptionKey === 'string')

  var errors = []

  function report (message, flag) {
    var error = new Error(message)
    error[flag] = true
    errors.push(error)
  }

  // Validate Signatures
  var ciphertext = envelope.entry.ciphertext
  var validLogSiganture = exports.verifyBinary(
    ciphertext, envelope.logSignature, logPublicKey
  )
  if (!validLogSiganture) {
    report('invalid log signature', 'logSignature')
  }
  var validProjectSignature = exports.verifyBinary(
    ciphertext, envelope.projectSignature, projectPublicKey
  )
  if (!validProjectSignature) {
    report('invalid project signature', 'projectSignature')
  }

  // Validate Entry
  if (encryptionKey) {
    var entry = exports.decryptJSON(
      envelope.entry.ciphertext,
      envelope.entry.nonce,
      encryptionKey
    )
    if (!entry) {
      report('could not decrypt entry', 'encryption')
    } else {
      if (entry.discoveryKey !== envelope.discoveryKey) {
        report('discoveryKey mismatch', 'discoveryKey')
      }
      if (entry.index !== envelope.index) {
        report('index mismatch', 'index')
      }
      if (entry.index > 0 && !envelope.hasOwnProperty('prior')) {
        report('envelope missing prior digest', 'envelopePrior')
      }
      if (entry.index > 0 && !entry.hasOwnProperty('prior')) {
        report('entry missing prior digest', 'entryPrior')
      }
    }
  }

  return errors
}

// Invitations

var invitationEncrypted = ['encryptionKey', 'secretKey', 'title']

exports.encryptInvitation = function (options) {
  var replicationKey = options.replicationKey
  assert(typeof replicationKey === 'string')
  var publicKey = options.publicKey
  assert(typeof publicKey === 'string')
  var encryptionKey = options.encryptionKey
  assert(typeof encryptionKey === 'string')

  var returned = { replicationKey, publicKey }
  invitationEncrypted.forEach(encryptProperty)
  return returned

  function encryptProperty (key) {
    if (!options.hasOwnProperty(key)) return
    var encryptMethod = key === 'title'
      ? exports.encryptString
      : exports.encryptBinary
    var nonce = exports.nonce()
    returned[key] = {
      ciphertext: encryptMethod(
        options[key], nonce, encryptionKey
      ),
      nonce
    }
  }
}

exports.decryptInvitation = function (options) {
  var invitation = options.invitation
  assert(typeof invitation === 'object')
  var encryptionKey = options.encryptionKey
  assert(typeof encryptionKey === 'string')

  var returned = {
    replicationKey: invitation.replicationKey,
    publicKey: invitation.publicKey
  }
  invitationEncrypted.forEach(decryptProperty)
  return returned

  function decryptProperty (key) {
    if (!invitation.hasOwnProperty(key)) return
    var decryptMethod = key === 'title'
      ? exports.decryptString
      : exports.decryptBinary
    returned[key] = decryptMethod(
      invitation[key].ciphertext,
      invitation[key].nonce,
      encryptionKey
    )
  }
}
