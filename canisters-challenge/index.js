const crypto = require("crypto");

const sign = {
  record: {
    principal: "2vxsx-fae",
    signature: [
      38, 11, 159, 18, 188, 18, 210, 54, 94, 144, 238, 202, 220, 86, 60, 209, 51, 62, 37, 234, 213,
      20, 228, 239, 9, 43, 41, 155, 19, 143, 90, 244, 52, 213, 202, 92, 2, 135, 208, 33, 163, 115,
      215, 36, 27, 214, 186, 204, 142, 168, 215, 188, 103, 249, 42, 187, 82, 176, 201, 106, 116,
      172, 240, 184,
    ],
    messageHash: [
      178, 182, 138, 98, 52, 79, 141, 7, 48, 233, 49, 217, 38, 109, 221, 60, 37, 89, 22, 86, 5, 156,
      56, 158, 214, 80, 209, 145, 51, 1, 173, 154,
    ],
  },
};

const principal = sign.record.principal;
let signature = Uint8Array.from(sign.record.signature);
const messageHash = Uint8Array.from(sign.record.messageHash);

const publicKey = Buffer.from(principal);

const verify = crypto.createVerify("SHA256");
verify.update(messageHash);
verify.end();

// Adjusting signature length if needed
console.log("signature.length = ", signature.length);
if (signature.length === 64) {
  signature = Buffer.concat([
    Buffer.from([0x30, 0x44, 0x02, 0x20]),
    signature.slice(0, 32),
    Buffer.from([0x02, 0x20]),
    signature.slice(32),
  ]);
}

const isValid = verify.verify({ key: publicKey, format: "der", type: "spki" }, signature);

console.log("isValid = ", isValid);
