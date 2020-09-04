import { TokenEncoder } from "../token-encoder";
import { TokenInfo } from "../../domain/token-info";

export class TokenEncoderStringSeparated implements TokenEncoder {
  private readonly _separator: string;

  constructor(separator: string) {
    this._separator = separator;
  }

  public decode(token: string): TokenInfo {
    const [tokenKey, tokenValue, expiry] = token.split(this._separator);
    const expire = Number(expiry);
    return { tokenKey, tokenValue, expire };
  }

  public encode(info: TokenInfo): string {
    return (
      info.tokenKey +
      this._separator +
      info.tokenValue +
      this._separator +
      info.expire
    );
  }
}
