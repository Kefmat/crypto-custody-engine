import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';

/**
 * Handles symmetric AES-256-GCM operations and secure memory management.
 * * @author Kefmat
 * @version 1.0.0
 */
export class CipherEngine {
    private static readonly ALGORITHM = 'aes-256-gcm';
    private static readonly IV_LENGTH = 12;
    private static readonly AUTH_TAG_LENGTH = 16;

    /**
     * Encrypts plaintext data using AES-256-GCM.
     * * @param key The 32-byte (256-bit) encryption key.
     * @param plaintext The string data to encrypt.
     * @returns A Buffer containing the concatenated IV, AuthTag, and Ciphertext.
     * @throws Error if the key length is not exactly 32 bytes.
     */
    public static encrypt(key: Uint8Array, plaintext: string): Buffer {
        if (key.length !== 32) throw new Error('Invalid key length for AES-256');
        
        const iv = randomBytes(this.IV_LENGTH);
        const cipher = createCipheriv(this.ALGORITHM, key, iv);
        
        let ciphertext = cipher.update(plaintext, 'utf8');
        ciphertext = Buffer.concat([ciphertext, cipher.final()]);
        
        const authTag = cipher.getAuthTag();
        return Buffer.concat([iv, authTag, ciphertext]);
    }

    /**
     * Decrypts ciphertext data previously encrypted with AES-256-GCM.
     * * @param key The 32-byte (256-bit) decryption key.
     * @param encryptedPayload Buffer containing IV, AuthTag, and Ciphertext.
     * @returns The UTF-8 encoded plaintext string.
     * @throws Error if decryption fails or authentication tag is invalid.
     */
    public static decrypt(key: Uint8Array, encryptedPayload: Buffer): string {
        const iv = encryptedPayload.subarray(0, this.IV_LENGTH);
        const authTag = encryptedPayload.subarray(this.IV_LENGTH, this.IV_LENGTH + this.AUTH_TAG_LENGTH);
        const ciphertext = encryptedPayload.subarray(this.IV_LENGTH + this.AUTH_TAG_LENGTH);

        const decipher = createDecipheriv(this.ALGORITHM, key, iv);
        decipher.setAuthTag(authTag);

        let plaintext = decipher.update(ciphertext);
        plaintext = Buffer.concat([plaintext, decipher.final()]);
        
        return plaintext.toString('utf8');
    }

    /**
     * Securely purges sensitive data from active memory by overwriting it with zeroes.
     * * @param buffer The Uint8Array containing sensitive material.
     */
    public static wipeMemory(buffer: Uint8Array): void {
        buffer.fill(0);
    }
}