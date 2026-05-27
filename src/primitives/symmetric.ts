import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';
import { Buffer } from 'buffer';

/**
 * Interface defining the standard structure for an encrypted package 
 * within the Enterprise Cryptographic Lifecycle Engine.
 */
export interface EncryptedPayload {
    ciphertext: Buffer;
    iv: Buffer;
    authTag: Buffer;
}

/**
 * Engine for symmetric AES-256-GCM operations.
 * Handles key generation, encryption, and authentication validation.
 * @author Kefmat
 * @version 1.2.0
 */
export class SymmetricEngine {
    private static readonly ALGORITHM = 'aes-256-gcm';
    private static readonly IV_LENGTH = 12;
    private static readonly KEY_LENGTH = 32;

    /**
     * Generates a cryptographically strong 256-bit key.
     * @returns A 32-byte Buffer containing the new key.
     */
    public static generateKey(): Buffer {
        return randomBytes(this.KEY_LENGTH);
    }

    /**
     * Encrypts plaintext buffer using AES-256-GCM.
     * @param plaintext The raw buffer to be encrypted.
     * @param key The 32-byte key for encryption.
     * @returns An EncryptedPayload object containing the ciphertext, IV, and auth tag.
     */
    public static encrypt(plaintext: Buffer, key: Buffer): EncryptedPayload {
        const iv = randomBytes(this.IV_LENGTH);
        const cipher = createCipheriv(this.ALGORITHM, key, iv);
        
        const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
        
        return { 
            ciphertext, 
            iv, 
            authTag: cipher.getAuthTag() 
        };
    }

    /**
     * Decrypts an EncryptedPayload and verifies the authentication tag.
     * @param payload The EncryptedPayload structure to decrypt.
     * @param key The 32-byte key used for decryption.
     * @returns The recovered plaintext Buffer.
     */
    public static decrypt(payload: EncryptedPayload, key: Buffer): Buffer {
        const decipher = createDecipheriv(this.ALGORITHM, key, payload.iv);
        decipher.setAuthTag(payload.authTag);
        
        return Buffer.concat([decipher.update(payload.ciphertext), decipher.final()]);
    }
}