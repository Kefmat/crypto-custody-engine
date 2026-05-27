import { Buffer } from 'buffer';

/**
 * Utility class to provide secure memory sanitization.
 * Overwrites sensitive buffers with zeroes to prevent memory forensics.
 * @author Kefmat
 * @version 1.0.1
 */
export class MemoryZeroizer {
    /**
     * Wipes a buffer or typed array by overwriting all indices with 0x00.
     * Checks for existence and the presence of the .fill() method.
     * * @param data The buffer or typed array to securely clear.
     */
    public static zeroizeBuffer(data: any): void {
        if (data && typeof data.fill === 'function') {
            data.fill(0);
        }
    }
}