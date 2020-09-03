/**
 * Creates and verifies hash codes
 */
export interface SecureHash {
  createHash(value: string): Promise<string>;
  verifyHash(value: string, hash: string): Promise<boolean>;
}
