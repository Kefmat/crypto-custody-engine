import { SymmetricEngine } from './primitives/symmetric.js';

/**
 * Execution harness to validate cryptographic primitives and integrity vectors.
 */
function runCryptographicValidation(): void {
    console.log('=================================================');
    console.log('       Cryptographic Custody Engine v1.0.0       ');
    console.log('=================================================\n');

    const sensitiveData = 'CONFIDENTIAL: Internal compliance audit targets scheduled for Q3.';
    console.log(`Original Plaintext: "${sensitiveData}"`);

    // 1. Key Generation
    const masterKey = SymmetricEngine.generateKey();
    console.log(`Generated Master Key (Hex): ${masterKey.toString('hex').substring(0, 32)}...`);

    // 2. Successful Encryption Loop
    const encrypted = SymmetricEngine.encrypt(sensitiveData, masterKey);
    console.log('\n--- Encryption Output ---');
    console.log(`Ciphertext: ${encrypted.ciphertext}`);
    console.log(`IV Vector:  ${encrypted.iv}`);
    console.log(`Auth Tag:   ${encrypted.authTag}`);

    // 3. Successful Decryption Loop
    const decrypted = SymmetricEngine.decrypt(encrypted, masterKey);
    console.log('\n--- Decryption Verification ---');
    console.log(`Decrypted Result: "${decrypted}" [SUCCESS]`);

    // 4. Attack Simulation (Tampering with the cipher stream)
    console.log('\n--- Simulating Malicious Tampering ---');
    
    // Corrupt the very last character of the ciphertext string to simulate a bit-flip attack
    const tamperedCiphertext = encrypted.ciphertext.substring(0, encrypted.ciphertext.length - 1) + '0';
    const tamperedPayload = {
        ...encrypted,
        ciphertext: tamperedCiphertext
    };

    console.log(`Altered Ciphertext: ${tamperedPayload.ciphertext}`);

    try {
        SymmetricEngine.decrypt(tamperedPayload, masterKey);
        console.log('Warning: Decrypted corrupted payload without error. Integrity check failed.');
    } catch (error: any) {
        console.log('Execution Blocked: Authentication tag validation failed.');
        console.log(`Reason: ${error.message} [INTEGRITY GUARANTEED]`);
    }
}

runCryptographicValidation();