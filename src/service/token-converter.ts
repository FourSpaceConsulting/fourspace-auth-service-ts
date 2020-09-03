
/**
 * Encode/decode token key/value to a string
 */
export interface TokenConverter {
    /**
     * decode token to key/value
     * @param token token
     */
    decode(token: string): [string, string];

    /**
     * encode key/value as string token 
     * @param key 
     * @param value 
     */
    encode(key: string, value: string): string;
}
