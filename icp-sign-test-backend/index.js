const crypto = require("crypto").webcrypto;

const signedPrincipal =
  "400262225a5acc79e030e5e933bc6d6ee3069d863c3f32d59188671eda5f14f2e05e61e4a4ddbf8dbc1fd657f097291671c1df3c61cf42cb50d0a1e32b913728";

const signatureBuffer = new Uint8Array(Buffer.from(signedPrincipal, "hex"));

const pubkey = delegation._delegation.delegations[0].delegation.pubkey;
const publicKeyBuffer = new Uint8Array(Buffer.from(pubkey, "hex"));

const dataTxt1 = delegation._principal.__principal__;
const dataTxt = delegation._delegation.publicKey;
const dataBuf = new Uint8Array(Buffer.from(dataTxt, "hex"));
const dataBuffer1 = new TextEncoder().encode(dataBuf);

function stringToArrayBuffer(str) {
  const buf = new ArrayBuffer(str.length * 2);
  const bufView = new Uint16Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

const publicKey = delegation._delegation.publicKey;
const expiration = delegation._delegation.delegations[0].delegation.expiration;
const dataString = expiration + publicKey;
console.log(dataString);
const dataBuffer3 = stringToArrayBuffer(dataString);
const dataBuf2 = new Uint8Array(Buffer.from(dataString, "hex"));
const dataBuffer = new TextEncoder().encode(dataBuf2);

(async () => {
  const publicKey = await crypto.subtle.importKey(
    "spki",
    publicKeyBuffer,
    {
      name: "ECDSA",
      namedCurve: "P-256",
    },
    true,
    ["verify"]
  );

  const isVerified = await crypto.subtle.verify(
    {
      name: "ECDSA",
      hash: { name: "SHA-256" },
    },
    publicKey,
    signatureBuffer,
    dataBuffer
  );

  console.log("isValid = ", isVerified);
})();
