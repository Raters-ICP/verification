// export const hexStringToArrayBuffer = (hexString: string) => {
//   console.log("hexString: ", hexString);
//   if (hexString.length % 2 !== 0) {
//     throw new Error("Hex string must have an even length");
//   }
//   const arrayBuffer = new ArrayBuffer(hexString.length / 2);
//   const uint8Array = new Uint8Array(arrayBuffer);
//   for (let i = 0; i < hexString.length; i += 2) {
//     uint8Array[i / 2] = parseInt(hexString.substr(i, 2), 16);
//   }
//   return arrayBuffer; // возвращает ArrayBuffer
// };

// export const createSignature = (hexString: string): Signature => {
//   const arrayBuffer = hexStringToArrayBuffer(hexString);
//   const signature = arrayBuffer as Signature;
//   return signature;
// };

// export const convertToPem = (keyBuffer: Buffer, keyType: string): string => {
//   const base64Key = keyBuffer.toString("base64");
//   const base64Chunks = base64Key ? base64Key.match(/.{1,64}/g) : null;
//   const pemKey = base64Chunks
//     ? `-----BEGIN ${keyType}-----\n${base64Chunks.join("\n")}\n-----END ${keyType}-----`
//     : "";
//   return pemKey;
// };

// function toBase64(arrayBuffer: Uint8Array): string {
//   return btoa(String.fromCharCode.apply(null, Array.from(arrayBuffer)));
// }

export function convertToPem(publicKey: Uint8Array, keyType: "PUBLIC" | "PRIVATE"): string {
  // const base64Key = toBase64(publicKey);
  const base64Key = btoa(String.fromCharCode.apply(null, Array.from(publicKey)));

  const lines = base64Key.match(/.{1,64}/g)?.join("\n");

  if (!lines) {
    throw new Error("Invalid key format");
  }

  const pemKey = `-----BEGIN ${keyType} KEY-----\n${lines}\n-----END ${keyType} KEY-----\n`;
  return pemKey;
}
