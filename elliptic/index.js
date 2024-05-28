const EC = require("elliptic").ec;
const nacl = require("tweetnacl");

const delegation = {
    delegations: [
      {
        delegation: {
          expiration: "17d3cecbdfa36000",
          pubkey: "3059301306072a8648ce3d020106082a8648ce3d0301070342000420084b1ebe3dc622f322a0cb381e06c46431b7c7ddec28dd256d78e033ad89a80bf43ef01fa0df36c40587d2dd4e16316e955092bb972502c7af2ece4a0f3d0b"
        },
        signature: "c45d3a1d878635c2e10dfbae08120d59c2f87b00d4e35057c8d6834ea7c7992ced4092088ad5e22ba3f15931d9ae366a59fe948135a54eb8d1018ee3717aaf05"
      }
    ],
    publicKey: "302a300506032b6570032100a66b42c55c8ba044a7277ebb5413e9c41dd284ef6ac2d2f9eb307f78edd672a4"
  }

const expiration = delegation.delegations[0].delegation.expiration;
const delegationSignature = delegation.delegations[0].signature;
// const delegationPubKey = delegation.delegations[0].delegation.pubkey;
// const publicKeyEd25519 = delegation.publicKey;
const delegationPubKey = delegation.delegations[0].delegation.pubkey;
const publicKeyEd25519 = delegation.publicKey;

// Декодирование ключей
function decodeECDSAPublicKey(key) {
  const keyBuffer = Buffer.from(key, "hex");
  const asn1 = require("asn1.js");
  const ECPublicKeyASN = asn1.define("ECPublicKey", function () {
    this.seq().obj(
      this.key("algorithm").seq().obj(this.key("id").objid(), this.key("curve").objid()),
      this.key("pub").bitstr()
    );
  });
  const decodedKey = ECPublicKeyASN.decode(keyBuffer, "der");
  return Buffer.from(decodedKey.pub.data);
}

function decodeEd25519PublicKey(key) {
  const keyBuffer = Buffer.from(key, "hex");
  return keyBuffer.slice(keyBuffer.length - 32);
}

// Верификация ECDSA
function verifyECDSA(pubKey, signature, data) {
  const ec = new EC("p256");
  const key = ec.keyFromPublic(pubKey, "hex");
  const r = signature.slice(0, 64);
  const s = signature.slice(64, 128);
  return key.verify(data, { r, s });
}

// Верификация Ed25519
function verifyEd25519(pubKey, signature, data) {
  const sigBuffer = Buffer.from(signature, "hex");
  return nacl.sign.detached.verify(data, sigBuffer, pubKey);
}

function verifyDelegation(delegationPubKey, delegationSignature, publicKeyEd25519) {
  const decodedECDSAPubKey = decodeECDSAPublicKey(delegationPubKey);
  const decodedEd25519PubKey = decodeEd25519PublicKey(publicKeyEd25519);
  const signatureBuffer = Buffer.from(delegationSignature, "hex");

  const data = Buffer.concat([
    Buffer.from(expiration, "hex"),
    Buffer.from(delegationPubKey, "hex"),
  ]);

  const isECDSAVerified = verifyECDSA(decodedECDSAPubKey, signatureBuffer, data);
  console.log('ECDSA verification result:   ', isECDSAVerified);

  const isEd25519Verified = verifyEd25519(decodedEd25519PubKey, signatureBuffer, data);
  console.log('Ed25519 verification result: ', isEd25519Verified);

}

verifyDelegation(delegationPubKey, delegationSignature, publicKeyEd25519);
