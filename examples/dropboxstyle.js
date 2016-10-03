const bcrypt = require('../bcrypt');
const crypto = require('crypto');
const algorithm = 'aes-256-ctr';
const aeskey = '627iKv{fEKv&]3M9gt#j2k32X6_[l&';

function encrypt(text){
  var cipher = crypto.createCipher(algorithm, aeskey);
  var crypted = cipher.update(text, 'utf8', 'hex');
  crypted += cipher.final('hex');
  return crypted;
}

function decrypt(text){
  var decipher = crypto.createDecipher(algorithm, aeskey);
  var dec = decipher.update(text, 'hex', 'utf8');
  dec += decipher.final('utf8');
  return dec;
}

const start = Date.now();

const password = 'password';

const hasher = crypto.createHash('sha512');
hasher.update(password);
const hashedPassword = hasher.digest();
console.log('sha512 hashed pass length: ' + hashedPassword.length)
console.log('sha512 hashed: ' + (Date.now() - start) + 'ms');

bcrypt.genSalt(10, function(err, salt) {
  console.log('salt: ' + salt);
  console.log('salt cb end: ' + (Date.now() - start) + 'ms');
  bcrypt.hash(hashedPassword, salt, function(err, crypted) {
    console.log('crypted: ' + crypted);
    console.log('crypted cb end: ' + (Date.now() - start) + 'ms');
    console.log('rounds used from hash:', bcrypt.getRounds(crypted));

    const encrypted = encrypt(crypted);
    console.log('aes encrypted: ' + encrypted);


    const decrypted = decrypt(encrypted);

    bcrypt.compare(hashedPassword, decrypted, function(err, res) {
      console.log('compared true: ' + res);
      console.log('compared true cb end: ' + (Date.now() - start) + 'ms');
    });
    bcrypt.compare(new Buffer('bacon'), decrypted, function(err, res) {
      console.log('compared false: ' + res);
      console.log('compared false cb end: ' + (Date.now() - start) + 'ms');
    });
  });
})

console.log('end: ' + (Date.now() - start) + 'ms');
