var tape = require('tape')
var crypto = require('./')

tape('encryption round trip', function (test) {
  var plaintext = crypto.randomBuffer(128)
  var key = crypto.makeProjectReadKey()
  var nonce = crypto.randomNonce()
  var encrypted = crypto.encrypt(plaintext, nonce, key)
  var decrypted = crypto.decrypt(encrypted, nonce, key)
  test.same(plaintext, decrypted, 'identical')
  test.end()
})
