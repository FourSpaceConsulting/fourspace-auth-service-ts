import {
  UserSecurityContext,
  UnauthenticatedContext
} from "../domain/security-context";
import { TokenDao } from "../dao/token-dao";
import { TokenAuthenticator } from "./token-authenticator";
import { SecureHash } from "./secure-hash";
import { TokenConverter } from "./token-converter";

/**
 * Authenticate users with a secure token
 */
export class TokenAuthenticatorImpl implements TokenAuthenticator {
  private static readonly UNAUTH: UserSecurityContext = UnauthenticatedContext;
  private readonly _tokenParser: TokenConverter;
  private readonly _tokenDao: TokenDao;
  private readonly _secureHash: SecureHash;

  constructor(
    tokenParser: TokenConverter,
    tokenDao: TokenDao,
    secureHash: SecureHash
  ) {
    this._tokenParser = tokenParser;
    this._tokenDao = tokenDao;
    this._secureHash = secureHash;
  }

  public async authenticateToken(token: string): Promise<UserSecurityContext> {
    const [tokenKey, tokenValue] = this._tokenParser.decode(token);
    const authToken = await this._tokenDao.getToken(tokenKey);
    if (
      authToken != null &&
      (await this._secureHash.verifyHash(tokenValue, authToken.hashToken))
    ) {
      return {
        isAuthenticated: true,
        principal: authToken.user
      };
    }
    return TokenAuthenticatorImpl.UNAUTH;
  }
}
