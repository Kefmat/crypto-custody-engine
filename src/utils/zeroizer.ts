import { Buffer } from 'buffer';

/**
 * Utility handling secure data sanitization inside volatile system memory.
 * Overwrites sensitive buffer vectors before garbage collection loops.
 * @author Kevin Matarewicz
 */
export class MemoryZeroizer {

    /**
     * Programmatically overwrites a Buffer with zeroes to destroy key material.
     * @param buffer The targeted sensitive binary material buffer.
     */
    public static zeroizeBuffer(buffer: Buffer | Uint8Array | null): void {
        if (!buffer) return;
        
        // Explicitly fill the underlying memory allocation space with 0x00 bytes
        buffer.fill(0);
    }

    /**
     * Attempts to safely clean or mask string representations of keys.
     * Note: Pure JS strings are immutable, so we overwrite references and recommend 
     * using Buffers for sensitive data pipelines.
     */
    public static clearStringReference(str: string): string {
        return '';
    }
}