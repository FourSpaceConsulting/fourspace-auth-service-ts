import { TokenInfo } from '../domain/token-info';

/**
 * Encode/decode token key/value to a string
 */
export interface TokenEncoder {
    /**
     * decode token to key/value
     * @param token token
     */
    decode(token: string): TokenInfo;

    /**
     * encode key/value as string token
     * @param key
     * @param value
     */
    encode(info: TokenInfo): string;
}
