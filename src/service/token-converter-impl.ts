import { TokenConverter } from "./token-converter";

export class TokenConverterImpl implements TokenConverter {
    private readonly _keyLength: number;

    constructor(keyLength: number) {
        this._keyLength = keyLength;
    }

    public decode(token: string): [string, string] {
        const tokenKey = token.substring(0, this._keyLength);
        const tokenValue = token.substring(this._keyLength);
        return [tokenKey, tokenValue];
    }

    public encode(key: string, value: string): string {
        return key + value;
    }

}