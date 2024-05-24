const { Principal } = require('@dfinity/principal');
const crypto = require('crypto');
const { DelegationChain, DelegationIdentity } = require('@dfinity/agent');
const secp256k1 = require('@noble/secp256k1');

  function convertToPem(keyBuffer, keyType) {
    const base64Key = keyBuffer.toString('base64');
    const pemKey = `-----BEGIN ${keyType}-----\n${base64Key.match(/.{1,64}/g).join('\n')}\n-----END ${keyType}-----`;
    return pemKey;
  }

// Ваши данные делегации
const delegations = [
  {
    delegation: {
      expiration: "17d232dc959f0180",
      pubkey: "3059301306072a8648ce3d020106082a8648ce3d03010703420004087241546c5e8ea0e45fd52b8b7a2ebeee62f2027e47de0f476f9a75c4e027c377696a1e31856aaf8de2a0c0c618e691fcb47e3cb52c3f218ae7f817b2f8ecb8",
    },
    signature: "e145f37edb802df8a9a968fca00264207e3777cf54bf8030b024cfbe540d1787612dfdaf5170ccf5dfb68e17a22d517b8c19adc49b99b7031f54fb0da34dad00",
  },
];
const publicKey = "302a300506032b6570032100a66b42c55c8ba044a7277ebb5413e9c41dd284ef6ac2d2f9eb307f78edd672a4";

const principal = Principal.selfAuthenticating(Buffer.from(publicKey, 'hex'));
console.log(`Principal: ${principal.toText()}`);


const delegation = delegations[0].delegation;
const signature = delegations[0].signature;
// const pubKey1 = convertToPem(      Buffer.from(publicKey, 'hex'),       'PUBLIC KEY',      );
// const pubKey2 = convertToPem(      Buffer.from(delegation.pubkey, 'hex'),       'PUBLIC KEY',      );
const pubKey3 = convertToPem(Buffer.from(delegation.expiration + delegation.pubkey, 'hex'));
const pubKey11 = publicKey;
const pubKey21 = delegation.pubkey;

 const message = Buffer.from(delegation.expiration + delegation.pubkey, 'hex');
  const signatureBuffer = Buffer.from(signature, 'hex');
  const pubkeyBuffer = Buffer.from(publicKey, 'hex');
  const isVerified = secp256k1.verify(signatureBuffer, message, pubkeyBuffer);


 console.log(`Signature verified: ${isVerified}`);