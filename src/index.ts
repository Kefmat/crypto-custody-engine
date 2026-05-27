import { randomBytes } from 'crypto';
import { ThresholdEngine, KeyShare } from './primitives/threshold.js';
import { CipherEngine } from './primitives/crypto.js';

/**
 * Main execution class for the Enterprise Cryptographic Lifecycle Engine.
 * Orchestrates key generation, sharding, encryption, wiping, and automated rotation.
 */
class EnterpriseLifecycle {
    /**
     * Executes the full cryptographic lifecycle demonstration.
     */
    public static async execute(): Promise<void> {
        console.log("=================================================");
        console.log("    Enterprise Cryptographic Lifecycle Engine    ");
        console.log("=================================================\n");

        const targetData = "Highly Confidential Enterprise Blueprint";

        // Phase 1: Initialize Active Key
        const activeKey = new Uint8Array(randomBytes(32));
        console.log(`[Phase 1] Active Key Initialized (Hex): ${Buffer.from(activeKey).toString('hex').substring(0, 32)}...`);

        // Phase 2: Split-Trust Sharding
        const threshold = 3;
        const totalShares = 5;
        const shares = ThresholdEngine.splitSecret(activeKey, threshold, totalShares);
        console.log(`[Phase 2] Executed ${threshold}-of-${totalShares} Split-Trust Sharding Ceremonies.`);

        // Diagnostic Check
        const selectedShares: KeyShare[][] = [shares[0], shares[2], shares[4]];
        const reconstructedKey = ThresholdEngine.reconstructSecret(selectedShares);
        console.log(`[Diagnostic] Immediate Key Reconstruction: ${Buffer.from(reconstructedKey).toString('hex').substring(0, 32)}...`);
        
        const isMatch = Buffer.compare(activeKey, reconstructedKey) === 0;
        console.log(`[Diagnostic] Match Original Key? ${isMatch ? 'YES' : 'NO'}`);

        // Phase 3: Encryption
        const initialCiphertext = CipherEngine.encrypt(activeKey, targetData);
        console.log(`[Phase 3] Data Encrypted. Initial Ciphertext: ${initialCiphertext.toString('hex').substring(0, 32)}...`);

        // Phase 4: Purge Working Key
        CipherEngine.wipeMemory(activeKey);
        console.log(`[Phase 4] Working Key Overwritten with Zeroes & Purged from RAM.\n`);

        console.log("--- Initiating Compliance-Driven Automated Key Rotation ---");

        // Rotation Phase: Reconstruct to migrate
        const migrationShares: KeyShare[][] = [shares[1], shares[2], shares[3]];
        const legacyKey = ThresholdEngine.reconstructSecret(migrationShares);
        console.log(`[Rotation] Key Reconstructed for Migration: ${Buffer.from(legacyKey).toString('hex').substring(0, 32)}...`);

        // Decrypt with legacy key
        const decryptedData = CipherEngine.decrypt(legacyKey, initialCiphertext);
        CipherEngine.wipeMemory(legacyKey); // Wipe immediately after use

        // Generate new rotational key and re-encrypt
        const newActiveKey = new Uint8Array(randomBytes(32));
        const newCiphertext = CipherEngine.encrypt(newActiveKey, decryptedData);
        CipherEngine.wipeMemory(newActiveKey); // Wipe active key
        
        console.log(`[Rotation] Migration Successful. New Ciphertext: ${newCiphertext.toString('hex').substring(0, 32)}...`);

        // Verification Phase (Simulating standard client access with new shards)
        const newShares = ThresholdEngine.splitSecret(newActiveKey, threshold, totalShares);
        const verificationKey = ThresholdEngine.reconstructSecret([newShares[0], newShares[1], newShares[4]]);
        const finalDecryption = CipherEngine.decrypt(verificationKey, newCiphertext);
        
        console.log(`[Verification] Decrypted Data matches original: ${finalDecryption === targetData}`);
    }
}

// Bootstrap the lifecycle execution
EnterpriseLifecycle.execute().catch(error => {
    console.error("Lifecycle Execution Failed:", error);
});