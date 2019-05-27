var tape = require('tape')
var crypto = require('./')

tape('encryption round trip', function (test) {
  var plaintext = 'plaintext message'
  var key = crypto.encryptionKey()
  var nonce = crypto.nonce()
  var encrypted = crypto.encryptString(plaintext, nonce, key)
  var decrypted = crypto.decryptString(encrypted, nonce, key)
  test.same(plaintext, decrypted, 'identical')
  test.end()
})

tape('bad decryption', function (test) {
  var random = crypto.random(64)
  var key = crypto.encryptionKey()
  var nonce = crypto.nonce()
  var decrypted = crypto.decryptString(random, nonce, key)
  test.assert(decrypted === false)
  test.end()
})

tape('binary encryption round trip', function (test) {
  var binary = crypto.random(32)
  var key = crypto.encryptionKey()
  var nonce = crypto.nonce()
  var encrypted = crypto.encryptBinary(binary, nonce, key)
  var decrypted = crypto.decryptBinary(encrypted, nonce, key)
  test.same(binary, decrypted, 'identical')
  test.end()
})

tape('binary bad decryption', function (test) {
  var random = crypto.random(32)
  var key = crypto.encryptionKey()
  var nonce = crypto.nonce()
  var decrypted = crypto.decryptBinary(random, nonce, key)
  test.assert(decrypted === false)
  test.end()
})

tape('signature', function (test) {
  var keyPair = crypto.keyPair()
  var object = { entry: 'plaintext message' }
  var signature = crypto.signJSON(object, keyPair.secretKey)
  test.assert(
    crypto.verifyJSON(object, signature, keyPair.publicKey)
  )
  test.end()
})

tape('signature with body key', function (test) {
  var keyPair = crypto.keyPair()
  var object = { text: 'plaintext message' }
  var signature = crypto.signJSON(object, keyPair.secretKey)
  test.assert(
    crypto.verifyJSON(object, signature, keyPair.publicKey)
  )
  test.end()
})

tape('signature with keys from seed', function (test) {
  var plaintext = 'plaintext message'
  var seed = crypto.keyPairSeed()
  var keyPair = crypto.keyPairFromSeed(seed)
  var object = { entry: plaintext }
  var signature = crypto.signJSON(object, keyPair.secretKey)
  test.assert(
    crypto.verifyJSON(object, signature, keyPair.publicKey)
  )
  test.end()
})

tape('hash', function (test) {
  var input = 'this is some input'
  var digest = crypto.hash(input)
  test.assert(typeof digest === 'string')
  test.end()
})

tape('hashJSON', function (test) {
  var input = { text: 'this is some input' }
  var digest = crypto.hashJSON(input)
  test.assert(typeof digest === 'string')
  test.end()
})

tape('random', function (test) {
  var random = crypto.random(32)
  test.assert(typeof random === 'string')
  test.end()
})

tape('read key', function (test) {
  var key = crypto.encryptionKey()
  test.assert(typeof key === 'string')
  test.end()
})

tape('discovery key', function (test) {
  var replicationKey = crypto.replicationKey()
  test.assert(typeof replicationKey === 'string')
  var projectDiscoverKey = crypto.discoveryKey(replicationKey)
  test.assert(typeof projectDiscoverKey === 'string')
  test.end()
})

tape('validate envelope', function (test) {
  var replicationKey = crypto.replicationKey()
  var discoveryKey = crypto.discoveryKey(replicationKey)
  var index = 1
  var prior = crypto.hash(crypto.random(64))
  var entry = {
    discoveryKey,
    index,
    prior,
    type: 'intro',
    name: 'Kyle E. Mitchell',
    device: 'laptop',
    timestamp: new Date().toISOString()
  }
  var logKeyPair = crypto.keyPair()
  var logPublicKey = logKeyPair.publicKey
  var projectKeyPair = crypto.keyPair()
  var projectPublicKey = projectKeyPair.publicKey
  var encryptionKey = crypto.encryptionKey()
  var nonce = crypto.nonce()
  var ciphertext = crypto.encryptJSON(entry, nonce, encryptionKey)
  var envelope = {
    discoveryKey,
    logPublicKey,
    index,
    prior,
    logSignature: crypto.signBinary(
      ciphertext, logKeyPair.secretKey
    ),
    projectSignature: crypto.signBinary(
      ciphertext, projectKeyPair.secretKey
    ),
    entry: { ciphertext, nonce }
  }
  var errors = crypto.validateEnvelope({
    envelope, projectPublicKey, encryptionKey
  })
  test.same(errors, [], 'no errors')
  test.end()
})

tape('envelope generate and validate', function (test) {
  var replicationKey = crypto.replicationKey()
  var discoveryKey = crypto.discoveryKey(replicationKey)
  var logKeyPair = crypto.keyPair()
  var logPublicKey = logKeyPair.publicKey
  var projectKeyPair = crypto.keyPair()
  var projectPublicKey = projectKeyPair.publicKey
  var encryptionKey = crypto.encryptionKey()
  var index = 1
  var prior = crypto.hash(crypto.random(64))
  var envelope
  test.doesNotThrow(function () {
    envelope = crypto.envelope({
      discoveryKey,
      logKeyPair,
      projectKeyPair,
      encryptionKey,
      index,
      prior,
      entry: {
        type: 'intro',
        name: 'Kyle E. Mitchell',
        device: 'laptop',
        timestamp: new Date().toISOString()
      }
    })
  }, '.envelope() does not throw')
  var errors = crypto.validateEnvelope({
    envelope, projectPublicKey, logPublicKey, encryptionKey
  })
  test.same(errors, [], '.validateEnvelope() returns no errors')
  test.end()
})

tape('invitation round trip', function (test) {
  var replicationKey = crypto.replicationKey()
  var keyPair = crypto.keyPair()
  var publicKey = keyPair.publicKey
  var secretKey = keyPair.secretKey
  var encryptionKey = crypto.encryptionKey()
  var title = 'Test Title'
  var invitation
  test.doesNotThrow(function () {
    invitation = crypto.encryptInvitation({
      replicationKey,
      publicKey,
      encryptionKey,
      secretKey,
      title
    })
  }, '.invitation() does not throw')
  var opened = crypto.decryptInvitation({
    invitation, encryptionKey
  })
  test.same(opened.secretKey, secretKey, 'secretKey')
  test.same(opened.encryptionKey, encryptionKey, 'encryptionKey')
  test.same(opened.title, title, 'title')
  test.end()
})
