import { SymmetricEngine, EncryptedPayload } from '../primitives/symmetric.js';
import { MemoryZeroizer } from './zeroizer.js';
import { Buffer } from 'buffer';

/**
 * Automates key lifecycle updates and data re-encryption migration routines.
 * @author Kevin Matarewicz
 */
export class KeyRotator {

    /**
     * Programmatically migrates an encrypted storage payload from an outdated key structure to a fresh master key structure.
     * @param outdatedPayload The current active ciphertext payload packet.
     * @param currentKey The active 32-byte key assigned to the payload.
     * @returns A structured tuple containing the new EncryptedPayload and the new generated Buffer key.
     */
    public static rotatePayloadKey(outdatedPayload: EncryptedPayload, currentKey: Buffer): { newPayload: EncryptedPayload, newKey: Buffer } {
        // 1. Decrypt the legacy data payload using the active key configuration
        const decryptedData = SymmetricEngine.decrypt(outdatedPayload, currentKey);

        // 2. Generate an independent, fresh 256-bit symmetric storage key asset
        const freshKey = SymmetricEngine.generateKey();

        // 3. Encrypt the asset data using the freshly generated key configuration
        const newPayload = SymmetricEngine.encrypt(decryptedData, freshKey);

        // 4. Secure Overwrite: Wipe out the outdated encryption key instantly from RAM
        MemoryZeroizer.zeroizeBuffer(currentKey);

        return {
            newPayload,
            newKey: freshKey
        };
    }
}