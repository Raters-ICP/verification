import { Injectable } from '@nestjs/common';
import * as crypto from 'crypto';

export interface RequestVerify {
  challenge: string;
  signedChallenge: {
    publicKey: string;
    signature: string;
  };
}

export interface ResponsetVerify {
  option1: boolean;
  option2: boolean;
}

@Injectable()
export class AuthService {
  verifyAuth(req: RequestVerify): ResponsetVerify {
    const encoding = 'base64';
    const challenge = Buffer.from(req.challenge, encoding);
    const publicKey = Buffer.from(req.signedChallenge.publicKey, encoding);
    const signature = Buffer.from(req.signedChallenge.signature, encoding);

    // Вариант 1
    const publicKey1 = `-----BEGIN PUBLIC KEY-----\n${req.signedChallenge.publicKey}\n-----END PUBLIC KEY-----`;
    const verify = crypto.createVerify('SHA256');
    verify.update(challenge);
    verify.end();
    const isValid1 = verify.verify(publicKey1, signature);
    console.log('isValid1 = ', isValid1);

    // Вариант 2
    const keyObject = crypto.createPublicKey({
      key: publicKey,
      format: 'der',
      type: 'spki',
    });

    const isValid2 = crypto.verify(null, challenge, keyObject, signature);

    console.log('isValid2 = ', isValid2);

    return { option1: isValid1, option2: isValid2 };
  }
}
