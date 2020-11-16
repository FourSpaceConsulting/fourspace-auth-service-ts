import { TokenEncoder } from '../token-encoder';
import { TokenInfo } from '../../domain/token-info';

export class TokenEncoderStringSeparated implements TokenEncoder {
    private readonly _separator: string;

    constructor(separator: string) {
        this._separator = separator;
    }

    public decode(token: string): TokenInfo {
        const [tokenKey, tokenValue, expiry] = token == null ? [null, null, null] : token.split(this._separator);
        const expire = expiry == null ? 0 : Buffer.from(expiry, 'base64').readDoubleBE();
        return { tokenKey, tokenValue, expire };
    }

    public encode(info: TokenInfo): string {
        const expiryDate = Buffer.alloc(8);
        expiryDate.writeDoubleBE(info.expire);
        return info.tokenKey + this._separator + info.tokenValue + this._separator + expiryDate.toString('base64');
    }
}
