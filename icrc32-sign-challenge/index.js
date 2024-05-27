const crypto = require('crypto');

const param1 = {
  challenge: "UjwgsORvEzp98TmB1cAIseNOoD9+GLyN/1DzJ5+jxZM=",
  signedChallenge: {
    publicKey: "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEOTdHYwpFTr/oPXOfLQcteymk8AQE41VwPQ1W7Xpm0Zt1AY4+5aOnMAbAIjXEchxPuGbPWqPqwntXMPs3w4rOaA==",
    signature: "bldf7qn7DC5NzTyX5kp4GpZHaEncE5/6n/Y8av3xjEwIVFAwmhyW0uM+WBXRTj4QbScot04dfaBXUOcSWF0IjQ=="
  }
}
const param = {
  challenge: "sP4kjfTOHor/i6yENH3jMvznV56NW4oOmsCa9oV0CKQ=",
  signedChallenge: {
    publicKey: "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEOTdHYwpFTr/oPXOfLQcteymk8AQE41VwPQ1W7Xpm0Zt1AY4+5aOnMAbAIjXEchxPuGbPWqPqwntXMPs3w4rOaA==",
    signature: "bldf7qn7DC5NzTyX5kp4GpZHaEncE5/6n/Y8av3xjEwIVFAwmhyW0uM+WBXRTj4QbScot04dfaBXUOcSWF0IjQ=="
  }
}

const encoding = 'base64'
const challenge = Buffer.from(param.challenge, encoding)
const publicKey = Buffer.from(param.signedChallenge.publicKey, encoding);
const signature = Buffer.from(param.signedChallenge.signature, encoding);


// Вариант 1
const publicKey1 = `-----BEGIN PUBLIC KEY-----\n${param.signedChallenge.publicKey}\n-----END PUBLIC KEY-----`;
const verify = crypto.createVerify('SHA256');
verify.update(challenge);
verify.end();
const isValid1 = verify.verify(publicKey1, signature);
console.log('isValid1 = ', isValid1);


// Вариант 2
const keyObject = crypto.createPublicKey({
  key: publicKey,
  format: 'der',
  type: 'spki'
});

const isValid = crypto.verify(
  null,
  challenge,
  keyObject,
  signature
);

console.log('isValid  = ', isValid);
