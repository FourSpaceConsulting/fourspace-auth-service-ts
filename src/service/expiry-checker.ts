/**
 * Checks an expiration date
 */
export interface ExpiryChecker {
    isValid(expiry: Date): boolean;
}
