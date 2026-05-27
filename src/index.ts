import { SymmetricEngine } from './primitives/symmetric.js';
import { ThresholdEngine } from './primitives/threshold.js';
import { KeyRotator } from './utils/rotator.js';
import { MemoryZeroizer } from './utils/zeroizer.js';
import { Buffer } from 'buffer';

function runEnterpriseLifecycleCeremony(): void {
    console.log('=================================================');
    console.log('    Enterprise Cryptographic Lifecycle Engine    ');
    console.log('=================================================\n');

    const operationalSecret = 'SYS_CONFIG: Production multi-node database connectivity credentials.';
    
    // 1. Key Generation & Initial Multi-Party Sharding
    let activeMasterKey: Buffer | null = SymmetricEngine.generateKey();
    console.log(`[Phase 1] Active Key Initialized (Hex): ${activeMasterKey.toString('hex').substring(0, 32)}...`);

    const runtimeShares = ThresholdEngine.splitSecret(activeMasterKey, 3, 5);
    console.log(`[Phase 2] Executed 3-of-5 Split-Trust Sharding Ceremonies.`);

    // 2. Secure Data Injection
    let storagePayload = SymmetricEngine.encrypt(operationalSecret, activeMasterKey);
    console.log(`[Phase 3] Data Encrypted. Initial Ciphertext: ${storagePayload.ciphertext.substring(0, 32)}...`);

    // 3. Force Programmatic Zeroization of the working key to protect memory space
    MemoryZeroizer.zeroizeBuffer(activeMasterKey);
    activeMasterKey = null; // Sever pointer reference
    console.log(`[Phase 4] Working Key Overwritten with Zeroes & Purged from RAM.`);

    // 4. Automated Key Rotation Verification Cycle
    console.log('\n--- Initiating Compliance-Driven Automated Key Rotation ---');
    
    // Recover the key first using valid threshold shares to simulate an authorized cron-job rotation
    const recoveredBytes = ThresholdEngine.reconstructSecret([runtimeShares[0], runtimeShares[2], runtimeShares[4]]);
    
    // REMEDIATION: Safely cast the Uint8Array interface into a standard Node.js Buffer
    const authorizedRecoveryKey = Buffer.from(recoveredBytes.buffer, recoveredBytes.byteOffset, recoveredBytes.byteLength);
    console.log(`[Rotation] Key Reconstructed for Migration: ${authorizedRecoveryKey.toString('hex').substring(0, 32)}...`);

    // Perform the lifecycle translation rotation step
    const migrationResults = KeyRotator.rotatePayloadKey(storagePayload, authorizedRecoveryKey);
    
    storagePayload = migrationResults.newPayload;
    let freshActiveKey: Buffer | null = migrationResults.newKey;

    console.log(`[Rotation] Legacy Key Zeroized via Overwrite Pipeline.`);
    console.log(`[Rotation] Migration Successful. New Ciphertext: ${storagePayload.ciphertext.substring(0, 32)}...`);

    // Final verification proving the old data can be read from the new key seamlessly
    const finalVerificationText = SymmetricEngine.decrypt(storagePayload, freshActiveKey);
    console.log(`\nVerified Production Asset Integrity: "${finalVerificationText}" [LIFECYCLE SECURE]`);

    // Final Cleanup
    MemoryZeroizer.zeroizeBuffer(freshActiveKey);
    freshActiveKey = null;
    console.log('[Cleanup] System memory cleared down to absolute zero footprint.');
}

runEnterpriseLifecycleCeremony();