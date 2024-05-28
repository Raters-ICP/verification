const EC = require("elliptic").ec;
const nacl = require("tweetnacl");

// Входные данные из JSON
const expiration = "17d3cbc7f4c87800"
const delegationPubKey =
  "3059301306072a8648ce3d020106082a8648ce3d03010703420004b7cea144553b94c460d8724b1df5d5dfb7eb6e8c616986fa8be95dde23dec7b910b32574974eda5da4411253fba8f3a23820ac3916f0382b79be9b8e0a79fcb8";
const delegationSignature =
  "6907f22143fb3dcbb9594b2819eb7cf9685bd189dcdbd0868f3c0afdcfe87b7b248b6485694650097396bf054671a080e76fc952f28d83baf8fda2c92f9d6008";
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

// Основная функция для верификации
function verifyDelegation(delegationPubKey, delegationSignature, publicKeyEd25519) {
  const decodedECDSAPubKey = decodeECDSAPublicKey(delegationPubKey);
  const decodedEd25519PubKey = decodeEd25519PublicKey(publicKeyEd25519);
  const signatureBuffer = Buffer.from(delegationSignature, "hex");

  // Пример данных для проверки (expiration + pubkey)
  const data = Buffer.concat([
    Buffer.from(expiration, "hex"),
    Buffer.from(delegationPubKey, "hex"),
  ]);

  const isECDSAVerified = verifyECDSA(decodedECDSAPubKey, signatureBuffer, data);
  console.log('ECDSA verification result: ', isECDSAVerified);

  const isEd25519Verified = verifyEd25519(decodedEd25519PubKey, signatureBuffer, data);
  console.log('Ed25519 verification result: ', isEd25519Verified);
}

// Запуск верификации
verifyDelegation(delegationPubKey, delegationSignature, publicKeyEd25519);
