var tape = require('tape')
var crypto = require('./')

tape('encryption round trip', function (test) {
  var plaintext = 'plaintext message'
  var key = crypto.makeProjectReadKey()
  var nonce = crypto.randomNonce()
  var encrypted = crypto.encrypt(plaintext, nonce, key)
  var decrypted = crypto.decrypt(encrypted, nonce, key)
  test.same(plaintext, decrypted, 'identical')
  test.end()
})

tape('signature', function (test) {
  var plaintext = 'plaintext message'
  var seed = crypto.makeSigningKeyPairSeed()
  var keyPair = crypto.makeSigningKeyPairFromSeed(seed)
  var object = { entry: plaintext }
  crypto.sign(object, keyPair.secretKey, 'signature')
  test.assert(crypto.verify(object, keyPair.publicKey, 'signature'))
  test.end()
})
