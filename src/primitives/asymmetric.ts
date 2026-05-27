import { generateKeyPairSync, sign, verify } from 'crypto';
import { Buffer } from 'buffer';

/**
 * Structured container for generated asymmetric cryptographic key assets.
 */
export interface AsymmetricKeyPair {
    /** The public key string formatted in standard PEM encoding. */
    publicKey: string;
    /** The private key string formatted in standard PEM encoding. */
    privateKey: string;
}

/**
 * Implements digital signature operations using the Ed25519 curve scheme.
 * Ensures data origin authentication and absolute transactional non-repudiation.
 * @author Kevin Matarewicz
 */
export class AsymmetricEngine {

    /**
     * Programmatically generates a raw Ed25519 signature key pair.
     * @returns A structured AsymmetricKeyPair container.
     */
    public static generateKeyPair(): AsymmetricKeyPair {
        const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        });

        return { publicKey, privateKey };
    }

    /**
     * Signs a data payload utilizing a private key construct.
     * @param data The raw data content string to sign.
     * @param privateKey The PEM-encoded private key asset.
     * @returns A hex string containing the generated signature.
     */
    public static signData(data: string, privateKey: string): string {
        const dataBuffer = Buffer.from(data, 'utf8');
        const signatureBuffer = sign(null, dataBuffer, privateKey);
        return signatureBuffer.toString('hex');
    }

    /**
     * Verifies the digital signature validity over a targeted data payload.
     * @param data The raw data content string that was supposedly signed.
     * @param signatureHex The hex-encoded signature to evaluate.
     * @param publicKey The PEM-encoded public key counterpart.
     * @returns True if the origin signature is completely authentic; false otherwise.
     */
    public static verifyData(data: string, signatureHex: string, publicKey: string): boolean {
        const dataBuffer = Buffer.from(data, 'utf8');
        const signatureBuffer = Buffer.from(signatureHex, 'hex');
        return verify(null, dataBuffer, publicKey, signatureBuffer);
    }
}