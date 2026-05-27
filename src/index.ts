import { SymmetricEngine } from './primitives/symmetric.js';
import { AsymmetricEngine } from './primitives/asymmetric.js';

/**
 * Execution harness to validate cryptographic primitives, integrity vectors, and identity signatures.
 */
function runCryptographicValidation(): void {
    console.log('=================================================');
    console.log('       Cryptographic Custody Engine v1.0.0       ');
    console.log('=================================================\n');

    const criticalPayload = 'AUDIT_RECORD: Security clearance granted to administrator root accounts.';
    console.log(`Original Asset Data: "${criticalPayload}"`);

    // 1. Establish Identity Infrastructure (Asymmetric Curve Scheme)
    console.log('\n--- Deploying Identity Keys ---');
    const officerIdentity = AsymmetricEngine.generateKeyPair();
    console.log('Generated Identity Public Key Profile:');
    console.log(officerIdentity.publicKey.trim().substring(0, 100) + '...\n[Ed25519 Active]');

    // 2. Compute Digital Signature (Proves Origin/Non-Repudiation)
    const signature = AsymmetricEngine.signData(criticalPayload, officerIdentity.privateKey);
    console.log(`Computed Origin Signature (Hex): ${signature.substring(0, 32)}...`);

    // 3. Encrypt the Asset Container (Proves Confidentiality/At-Rest Integrity)
    const storageKey = SymmetricEngine.generateKey();
    const encryptedAsset = SymmetricEngine.encrypt(criticalPayload, storageKey);
    console.log('\n--- Asset Sealed for Storage ---');
    console.log(`Ciphertext: ${encryptedAsset.ciphertext.substring(0, 32)}...`);
    console.log(`GCM Auth Tag: ${encryptedAsset.authTag}`);

    // 4. Recovery & Verification Flow (The Receiver Processing Step)
    console.log('\n--- Running Complete Verification Processing ---');
    
    // Step A: Decrypt and confirm data was not altered at rest
    const recoveredData = SymmetricEngine.decrypt(encryptedAsset, storageKey);
    console.log(`Step A: Symmetric Decryption Verified: "${recoveredData}"`);

    // Step B: Verify the digital signature to prove identity
    const isSignatureValid = AsymmetricEngine.verifyData(recoveredData, signature, officerIdentity.publicKey);
    console.log(`Step B: Identity Signature Authenticated: [${isSignatureValid ? 'SUCCESS' : 'FAILED'}]`);

    // 5. Spoofing Attack Simulation (Modifying data while maintaining a valid GCM tag)
    console.log('\n--- Simulating Identity Spoofing Attack ---');
    const alteredData = 'AUDIT_RECORD: Security clearance granted to rogue malicious accounts.';
    
    // An insider encrypts a different payload cleanly using the symmetric storage key
    const forgedEncryption = SymmetricEngine.encrypt(alteredData, storageKey);
    const recoveredForgedData = SymmetricEngine.decrypt(forgedEncryption, storageKey);
    
    console.log(`Decrypted Forged Payload: "${recoveredForgedData}" [Symmetric Cipher Passed]`);

    // Check the original officer's signature against the new data package
    const isForgedSignatureValid = AsymmetricEngine.verifyData(recoveredForgedData, signature, officerIdentity.publicKey);
    console.log(`Evaluating Officer Signature Over Forged Payload: [${isForgedSignatureValid ? 'SUCCESS' : 'BLOCKED - SIGNATURE INVALID'}]`);
}

runCryptographicValidation();