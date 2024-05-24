// import initSigVerifier, { verifyIcSignature } from '@dfinity/standalone-sig-verifier-web';
const { initSigVerifier, verifyIcSignature } = require('@dfinity/standalone-sig-verifier-web');

async function example(dataRaw, signatureRaw, derPublicKey, root_key) {
    // load wasm module
    await initSigVerifier();
    try {
        // call the signature verification wasm function
        verifyIcSignature(dataRaw, signatureRaw, derPublicKey, root_key);
        console.log('Signature verified successfully');
    } catch (error) {
        // the library throws an error if the signature is invalid
        console.error('Signature verification failed:', error);
    }
}

const paramsSrc = {
  delegations: [
    {
      delegation: {
        expiration: "17d232dc959f0180",
        pubkey:
          "3059301306072a8648ce3d020106082a8648ce3d03010703420004087241546c5e8ea0e45fd52b8b7a2ebeee62f2027e47de0f476f9a75c4e027c377696a1e31856aaf8de2a0c0c618e691fcb47e3cb52c3f218ae7f817b2f8ecb8",
      },
      signature:
        "e145f37edb802df8a9a968fca00264207e3777cf54bf8030b024cfbe540d1787612dfdaf5170ccf5dfb68e17a22d517b8c19adc49b99b7031f54fb0da34dad00",
    },
  ],
  publicKey:
    "302a300506032b6570032100a66b42c55c8ba044a7277ebb5413e9c41dd284ef6ac2d2f9eb307f78edd672a4",
};

// Тестовые данные для проверки подписи
const dataRaw = "Example data to be signed";
const signatureRaw = paramsSrc.delegations[0].signature;
const derPublicKey = paramsSrc.delegations[0].delegation.pubkey;
const root_key = paramsSrc.publicKey;

// Вызов функции для проверки подписи
example(dataRaw, signatureRaw, derPublicKey, root_key);
