var tape = require('tape')
var crypto = require('./')

tape('encryption round trip', function (test) {
  var plaintext = 'plaintext message'
  var key = crypto.projectReadKey()
  var nonce = crypto.randomNonce()
  var encrypted = crypto.encrypt(plaintext, nonce, key)
  var decrypted = crypto.decrypt(encrypted, nonce, key)
  test.same(plaintext, decrypted, 'identical')
  test.end()
})

tape('bad decryption', function (test) {
  var random = Buffer.from(crypto.random(64), 'hex')
    .toString(crypto.ciphertextEncoding)
  var key = crypto.projectReadKey()
  var nonce = crypto.randomNonce()
  var decrypted = crypto.decrypt(random, nonce, key)
  test.assert(decrypted === false)
  test.end()
})

tape('signature', function (test) {
  var plaintext = 'plaintext message'
  var keyPair = crypto.signingKeyPair()
  var object = { entry: plaintext }
  crypto.sign(object, keyPair.secretKey, 'signature')
  test.assert(crypto.verify(object, keyPair.publicKey, 'signature'))
  test.end()
})

tape('signature with keys from seed', function (test) {
  var plaintext = 'plaintext message'
  var seed = crypto.signingKeyPairSeed()
  var keyPair = crypto.signingKeyPairFromSeed(seed)
  var object = { entry: plaintext }
  crypto.sign(object, keyPair.secretKey, 'signature')
  test.assert(crypto.verify(object, keyPair.publicKey, 'signature'))
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
  var key = crypto.projectReadKey()
  test.assert(typeof key === 'string')
  test.end()
})

tape('discovery key', function (test) {
  var projectReplicationKey = crypto.projectReplicationKey()
  test.assert(typeof projectReplicationKey === 'string')
  var projectDiscoverKey = crypto.discoveryKey(projectReplicationKey)
  test.assert(typeof projectDiscoverKey === 'string')
  test.end()
})
