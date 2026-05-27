import { randomBytes } from 'crypto';

/**
 * Represents a single coordinate point on the polynomial curve.
 * Used to store an individual key share.
 */
export interface KeyShare {
    x: number;
    y: number;
}

/**
 * Engine for splitting and reconstructing cryptographic secrets using Shamir's Secret Sharing.
 * Operates strictly over a Galois Field GF(2^8) using the AES irreducible polynomial.
 * * @author Kefmat
 * @version 1.1.0
 */
export class ThresholdEngine {
    /** The irreducible polynomial for AES GF(2^8). */
    private static readonly PRIMITIVE = 0x11b; 
    
    /** Lookup table for exponentiation in GF(2^8). */
    private static readonly EXP_TABLE = new Uint8Array(256);
    
    /** Lookup table for logarithms in GF(2^8). */
    private static readonly LOG_TABLE = new Uint8Array(256);

    /**
     * Statically initializes the lookup tables for Galois Field multiplication and division.
     * Utilizes 3 as the primitive generator to guarantee a full mathematical period of 255.
     */
    static {
        let x = 1;
        for (let i = 0; i < 255; i++) {
            this.EXP_TABLE[i] = x;
            this.LOG_TABLE[x] = i;
            
            let x2 = x << 1;
            if (x2 & 0x100) x2 ^= this.PRIMITIVE;
            x = x2 ^ x; 
        }
        this.EXP_TABLE[255] = this.EXP_TABLE[0];
    }

    /**
     * Cryptographically splits a secret buffer into multiple independent shares.
     * * @param secret The raw binary data to protect.
     * @param threshold Minimum number of shares required to reconstruct the secret.
     * @param totalShares The total number of shares to distribute.
     * @returns A two-dimensional array of KeyShare objects mapping to each byte for each participant.
     * @throws Error if the threshold configuration is mathematically invalid.
     */
    public static splitSecret(secret: Uint8Array, threshold: number, totalShares: number): KeyShare[][] {
        if (threshold > totalShares || threshold < 2 || totalShares > 255) {
            throw new Error('Invalid threshold configuration.');
        }

        const shares: KeyShare[][] = Array.from({ length: totalShares }, () => []);
        const entropyPool = randomBytes(secret.length * (threshold - 1));
        let poolIndex = 0;

        for (let b = 0; b < secret.length; b++) {
            const coefficients = new Uint8Array(threshold);
            coefficients[0] = secret[b]; 
            for (let i = 1; i < threshold; i++) {
                coefficients[i] = entropyPool[poolIndex++];
            }

            for (let shareX = 1; shareX <= totalShares; shareX++) {
                let y = 0;
                for (let i = 0; i < threshold; i++) {
                    let xToTheI = 1;
                    for (let j = 0; j < i; j++) {
                        xToTheI = this.galoisMultiply(xToTheI, shareX);
                    }
                    y ^= this.galoisMultiply(coefficients[i], xToTheI);
                }
                shares[shareX - 1].push({ x: shareX, y });
            }
        }
        return shares;
    }

    /**
     * Reconstructs the original secret buffer via Lagrange interpolation.
     * * @param providedShares The array of share vectors collected from participants.
     * @returns The fully reconstructed binary secret.
     * @throws Error if invalid coordinates are provided.
     */
    public static reconstructSecret(providedShares: KeyShare[][]): Uint8Array {
        const byteLength = providedShares[0].length;
        const secretBuffer = new Uint8Array(byteLength);

        for (let b = 0; b < byteLength; b++) {
            let secretByte = 0;
            for (let i = 0; i < providedShares.length; i++) {
                const xi = providedShares[i][b].x;
                const yi = providedShares[i][b].y;
                if (xi === 0) throw new Error('Security Fault: Share coordinate x cannot be 0.');

                let numAccumulator = 1;
                let denAccumulator = 1;
                for (let j = 0; j < providedShares.length; j++) {
                    if (i !== j) {
                        const xj = providedShares[j][b].x;
                        numAccumulator = this.galoisMultiply(numAccumulator, xj);
                        denAccumulator = this.galoisMultiply(denAccumulator, xi ^ xj);
                    }
                }
                if (denAccumulator !== 0) {
                    secretByte ^= this.galoisMultiply(yi, this.galoisDivide(numAccumulator, denAccumulator));
                }
            }
            secretBuffer[b] = secretByte;
        }
        return secretBuffer;
    }

    /**
     * Executes multiplication within the Galois Field using lookup tables.
     * * @param a First multiplicand.
     * @param b Second multiplicand.
     * @returns The product of a and b within GF(2^8).
     */
    private static galoisMultiply(a: number, b: number): number {
        if (a === 0 || b === 0) return 0;
        const sum = this.LOG_TABLE[a] + this.LOG_TABLE[b];
        return this.EXP_TABLE[sum >= 255 ? sum - 255 : sum];
    }

    /**
     * Executes division within the Galois Field using lookup tables.
     * * @param a The dividend.
     * @param b The divisor.
     * @returns The quotient of a and b within GF(2^8).
     * @throws Error if attempting to divide by zero.
     */
    private static galoisDivide(a: number, b: number): number {
        if (b === 0) throw new Error('Mathematical Fault: Division by zero.');
        if (a === 0) return 0;
        const diff = this.LOG_TABLE[a] - this.LOG_TABLE[b];
        return this.EXP_TABLE[diff < 0 ? diff + 255 : diff];
    }
}