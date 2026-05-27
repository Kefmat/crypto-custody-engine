import { SymmetricEngine, EncryptedPayload } from '../primitives/symmetric.js';
import { MemoryZeroizer } from './zeroizer.js';
import { Buffer } from 'buffer';

/**
 * Service responsible for the automated lifecycle rotation of cryptographic keys.
 * Ensures that payloads are re-wrapped with fresh entropy and that sensitive 
 * buffers (keys and plaintext) are wiped from memory immediately after use.
 * * @author Kefmat
 * @version 1.1.0
 */
export class KeyRotator {
    
    /**
     * Performs a formal rotation. Decrypts an existing payload and re-encrypts it 
     * using a newly generated key, then purges the legacy material.
     * * @param outdatedPayload The currently encrypted data structure.
     * @param currentKey The 32-byte key used for the current session.
     * @returns An object containing the new payload and the freshly generated key.
     */
    public static rotatePayloadKey(
        outdatedPayload: EncryptedPayload, 
        currentKey: Buffer
    ): { newPayload: EncryptedPayload, newKey: Buffer } {
        
        // 1. Recover the plaintext using the current (outdated) key
        const decryptedData = SymmetricEngine.decrypt(outdatedPayload, currentKey);
        
        // 2. Generate a fresh key for the new epoch
        const freshKey = SymmetricEngine.generateKey();
        
        // 3. Encrypt the data with the fresh key
        const newPayload = SymmetricEngine.encrypt(decryptedData, freshKey);

        // 4. Compliance-driven memory sanitization
        // Purge the old key and the transient plaintext from memory
        MemoryZeroizer.zeroizeBuffer(currentKey);
        MemoryZeroizer.zeroizeBuffer(decryptedData);

        return { 
            newPayload, 
            newKey: freshKey 
        };
    }
}