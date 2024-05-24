import { Injectable } from '@nestjs/common';
import * as crypto from 'crypto';

export interface InternetIdentityAuthResponse {
  delegations: {
    delegation: {
      pubkey: string; // Use string for hex values
      expiration: string; // Use string for hex values
    };
    signature: string; // Use string for hex values
  }[];
  publicKey: string; // Use string for hex values
}

@Injectable()
export class AuthService {
  verifyInternetIdentityAuth(response: InternetIdentityAuthResponse): boolean {
    if (!response || !response.publicKey || !response.delegations) {
      console.error('Invalid response format');
      return false;
    }

    const pubKey11 = this.convertToPem(
      Buffer.from(response.publicKey, 'hex'),
      'PUBLIC KEY',
    );
    const pubKey12 = response.publicKey;

    for (const delegation of response.delegations) {
      const pubKey21 = this.convertToPem(
        Buffer.from(delegation.delegation.pubkey, 'hex'),
        'PUBLIC KEY',
      );
      const pubKey22 = delegation.delegation.pubkey;
      const signature = Buffer.from(delegation.signature, 'hex');
      const expiration = BigInt('0x' + delegation.delegation.expiration);

      console.log('pubKey11: ', pubKey11);
      console.log('pubKey12: ', pubKey12);
      console.log('pubKey21: ', pubKey21);
      console.log('pubKey22: ', pubKey22);
      console.log('signature: ', signature);

      const verify = crypto.createVerify('SHA256');
      verify.update(pubKey12);
      verify.end();

      try {
        const isValid = verify.verify(pubKey22, signature);
        console.log('isValid: ', isValid);
        if (!isValid) {
          console.error('Invalid signature');
          return false;
        }
      } catch (error) {
        console.error('Verification error:', (error as Error).message);
        return false;
      }

      const currentTime = BigInt(Date.now());
      if (currentTime > expiration) {
        console.error('Delegation expired');
        return false;
      }
    }

    return true;
  }

  private convertToPem(keyBuffer: Buffer, keyType: string): string {
    const base64Key = keyBuffer.toString('base64');
    const pemKey = `-----BEGIN ${keyType}-----\n${base64Key.match(/.{1,64}/g).join('\n')}\n-----END ${keyType}-----`;
    return pemKey;
  }
}
