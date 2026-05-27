import { randomBytes } from 'crypto';
import { Buffer } from 'buffer';

/**
 * Structured container for an isolated cryptographic key share.
 */
export interface KeyShare {
    /** The X coordinate on the polynomial grid. */
    x: number;
    /** The Y value (the evaluation share byte) formatted as a hex string. */
    y: string;
}

/**
 * Implements an M-of-N Shamir's Secret Sharing threshold architecture.
 * Ensures multi-party custody overheads are met before reconstructing secrets.
 * @author Kevin Matarewicz
 */
export class ThresholdEngine {
    // Prime number for Galois Field (GF(256)) arithmetic definitions
    private static readonly PRIMITIVE = 0x11b; // AES field polynomial: x^8 + x^4 + x^3 + x + 1
    private static readonly EXP_TABLE = new Uint8Array(256);
    private static readonly LOG_TABLE = new Uint8Array(256);

    // Statically initialize log/exp lookup tables for rapid Galois Field multiplication
    static {
        let x = 1;
        for (let i = 0; i < 255; i++) {
            this.EXP_TABLE[i] = x;
            this.LOG_TABLE[x] = i;
            x <<= 1;
            if (x & 0x100) {
                x ^= this.PRIMITIVE;
            }
        }
        this.EXP_TABLE[255] = this.EXP_TABLE[0];
    }

    /**
     * Splits a master key buffer into N unique shares requiring an M threshold for recovery.
     * @param secret The raw 32-byte master key buffer asset.
     * @param threshold (M) The exact minimum number of shares needed to reconstruct.
     * @param totalShares (N) The total number of shares to generate.
     */
    public static splitSecret(secret: Buffer, threshold: number, totalShares: number): KeyShare[][] {
        if (threshold > totalShares || threshold < 2 || totalShares > 255) {
            throw new Error('Invalid threshold parameter mapping configuration.');
        }

        // DEEP COPY REMEDIATION: Clone the secret buffer into a completely isolated chunk of memory
        // This ensures subsequent programmatic zeroization of the original key does not corrupt our shares.
        const secretClone = Buffer.from(secret);

        // Initialize empty share lists for each individual participant slice
        const shares: KeyShare[][] = Array.from({ length: totalShares }, () => []);

        // Process every byte of the secret clone independently across a unique polynomial curve
        for (let b = 0; b < secretClone.length; b++) {
            const secretByte = secretClone[b];
            
            // Generate random coefficients for a polynomial of degree (threshold - 1)
            const coefficients = new Uint8Array(threshold);
            coefficients[0] = secretByte; // f(0) is our secret byte
            
            // Safe, isolated byte assignment to avoid sharing underlying ArrayBuffer views
            const randomCoeffs = randomBytes(threshold - 1);
            for (let i = 1; i < threshold; i++) {
                coefficients[i] = randomCoeffs[i - 1];
            }

            // Evaluate the polynomial for each participant X coordinate (1 to totalShares)
            for (let x = 1; x <= totalShares; x++) {
                let y = coefficients[0];
                
                for (let i = 1; i < threshold; i++) {
                    const coeff = coefficients[i];
                    if (coeff !== 0) {
                        let xToTheI = 1;
                        for (let j = 0; j < i; j++) {
                            xToTheI = this.galoisMultiply(xToTheI, x);
                        }
                        y ^= this.galoisMultiply(coeff, xToTheI);
                    }
                }
                
                shares[x - 1].push({ x, y: y.toString(16).padStart(2, '0') });
            }
        }

        return shares;
    }

    /**
     * Reconstructs the master key using Lagrange polynomial interpolation over GF(256).
     * @param providedShares An array containing at least M selected key share bundles.
     * @returns The recovered 32-byte master key Buffer.
     */
    public static reconstructSecret(providedShares: KeyShare[][]): Buffer {
        if (providedShares.length === 0) throw new Error('No shares submitted for evaluation.');
        
        const byteLength = providedShares[0].length;
        const secretBuffer = Buffer.alloc(byteLength);

        // Reconstruct each byte independently using Lagrange constants
        for (let b = 0; b < byteLength; b++) {
            let secretByte = 0;

            for (let i = 0; i < providedShares.length; i++) {
                const xi = providedShares[i][b].x;
                const yi = parseInt(providedShares[i][b].y, 16);
                
                let li = 1;
                for (let j = 0; j < providedShares.length; j++) {
                    if (i !== j) {
                        const xj = providedShares[j][b].x;
                        const numerator = xj;
                        const denominator = xi ^ xj;
                        const fraction = this.galoisDivide(numerator, denominator);
                        li = this.galoisMultiply(li, fraction);
                    }
                }
                secretByte ^= this.galoisMultiply(yi, li);
            }
            secretBuffer[b] = secretByte;
        }

        return secretBuffer;
    }

    private static galoisMultiply(a: number, b: number): number {
        if (a === 0 || b === 0) return 0;
        return this.EXP_TABLE[(this.LOG_TABLE[a] + this.LOG_TABLE[b]) % 255];
    }

    private static galoisDivide(a: number, b: number): number {
        if (b === 0) throw new Error('Division by zero inside Galois Field scope.');
        if (a === 0) return 0;
        return this.EXP_TABLE[(this.LOG_TABLE[a] - this.LOG_TABLE[b] + 255) % 255];
    }
}