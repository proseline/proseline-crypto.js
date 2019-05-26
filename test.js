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
  var keyPair = crypto.signingKeyPair()
  var object = { entry: 'plaintext message' }
  var signature = crypto.signJSON(object, keyPair.secretKey)
  test.assert(
    crypto.verifyJSON(object, signature, keyPair.publicKey)
  )
  test.end()
})

tape('signature with body key', function (test) {
  var keyPair = crypto.signingKeyPair()
  var object = { text: 'plaintext message' }
  var signature = crypto.signJSON(object, keyPair.secretKey)
  test.assert(
    crypto.verifyJSON(object, signature, keyPair.publicKey)
  )
  test.end()
})

tape('signature with keys from seed', function (test) {
  var plaintext = 'plaintext message'
  var seed = crypto.signingKeyPairSeed()
  var keyPair = crypto.signingKeyPairFromSeed(seed)
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
