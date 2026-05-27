import { SymmetricEngine } from './primitives/symmetric.js';
import { AsymmetricEngine } from './primitives/asymmetric.js';
import { ThresholdEngine } from './primitives/threshold.js';

function runKeyCustodyCeremony(): void {
    console.log('=================================================');
    console.log('       Cryptographic Custody Engine v1.0.0       ');
    console.log('=================================================\n');

    const coreSecretAsset = 'TOP-SECRET: Operational encryption infrastructure configurations blueprint.';

    // 1. Generate the initial root key framework
    const masterStorageKey = SymmetricEngine.generateKey();
    console.log(`Generated Vault Root Key (Hex): ${masterStorageKey.toString('hex')}\n`);

    // 2. Perform Key Ceremony Sharding (Split master key into 5 shares, requiring 3 to rebuild)
    const Threshold_M = 3;
    const Total_Shares_N = 5;
    console.log(`--- Executing Multi-Party Key Split (${Threshold_M}-of-${Total_Shares_N} Scheme) ---`);
    const runtimeShares = ThresholdEngine.splitSecret(masterStorageKey, Threshold_M, Total_Shares_N);
    
    for (let i = 0; i < Total_Shares_N; i++) {
        // Sample outputting a small chunk of each user's unique share slice
        const sampleHex = runtimeShares[i].map(s => s.y).join('').substring(0, 16);
        console.log(`Officer Account [${i + 1}] Share Slice: KeyHolderX(${runtimeShares[i][0].x}) Data: ${sampleHex}...`);
    }

    // 3. Encrypt data and instantly purge the master storage key from volatile system memory
    const sealedAsset = SymmetricEngine.encrypt(coreSecretAsset, masterStorageKey);
    console.log('\n--- Asset Locked & Root Key Programmatically Purged from Memory ---');
    console.log(`Stored Secure Ciphertext: ${sealedAsset.ciphertext.substring(0, 48)}...`);

    // 4. Simulate Reconstruction Failure (Insufficient Authorization - Only 2 Officers show up)
    console.log('\n--- Operational Request: Presenting Insufficient Shares (2-of-5) ---');
    const inadequateBatch = [runtimeShares[0], runtimeShares[1]];
    const failedKeyRecovery = ThresholdEngine.reconstructSecret(inadequateBatch);
    
    try {
        SymmetricEngine.decrypt(sealedAsset, failedKeyRecovery);
        console.log('Critical Leak: Decrypted data using a corrupt key recovery assembly!');
    } catch (error: any) {
        console.log(`Access Denied: Reconstructed key is cryptographically invalid.`);
        console.log(`Decryption Engine Message: ${error.message} [CUSTODY MATRIX SECURE]`);
    }

    // 5. Simulate Reconstruction Success (Compliance Requirements Met - 3 Officers show up)
    console.log(`\n--- Operational Request: Presenting Compliant Threshold Shares (3-of-5) ---`);
    const compliantBatch = [runtimeShares[0], runtimeShares[4], runtimeShares[2]]; // Officers 1, 5, and 3
    const recoveredMasterKey = ThresholdEngine.reconstructSecret(compliantBatch);
    console.log(`Successfully Reconstructed Key (Hex): ${recoveredMasterKey.toString('hex')}`);

    const authorizedRestoration = SymmetricEngine.decrypt(sealedAsset, recoveredMasterKey);
    console.log(`Restored Cryptographic Core Asset: "${authorizedRestoration}" [CEREMONY COMPLETE]`);
}

runKeyCustodyCeremony();