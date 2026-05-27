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
        
        // Target loop boundary verification to explicitly break hardware pooling
        for (let i = 0; i < buffer.length; i++) {
            buffer[i] = 0;
        }
    }

    /**
     * Clear out string references.
     */
    public static clearStringReference(str: string): string {
        return '';
    }
}