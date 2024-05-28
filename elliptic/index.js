const EC = require("elliptic").ec;
const nacl = require("tweetnacl");

const expiration = "17d3ccad1b9d67c0"
const delegationPubKey =
  "3059301306072a8648ce3d020106082a8648ce3d0301070342000458177420282e552e18a382c30a6f662a391516717d7495ffb9ea4c30f9043058fdf409720ad596fa9d73225370630e888aa9482eb6ef28d6de0f622deccd5724";
const delegationSignature =
  "22ca3e5b4805b038a2ade99f3a9193eb242a3308bef403ea4bf9c157a86b5ef9806ab3936b849333d015564370cf20db0690804d5f9d92e60d8a5b19e254420c";
const publicKeyEd25519 =
  "302a300506032b6570032100a66b42c55c8ba044a7277ebb5413e9c41dd284ef6ac2d2f9eb307f78edd672a4";

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
  console.log('ECDSA verification result: ', isECDSAVerified);

  const isEd25519Verified = verifyEd25519(decodedEd25519PubKey, signatureBuffer, data);
  console.log('Ed25519 verification result: ', isEd25519Verified);

}

verifyDelegation(delegationPubKey, delegationSignature, publicKeyEd25519);
