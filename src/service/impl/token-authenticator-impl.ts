import {
  UserSecurityContext,
  UnauthenticatedContext
} from "../../domain/security-context";
import { TokenDao } from "../../dao/token-dao";
import { TokenAuthenticator } from "./../token-authenticator";
import { SecureHash } from "./../secure-hash";
import { TokenEncoder } from "../token-encoder";
import { AuthTokenClaim } from "../../domain/auth-claim";

/**
 * Authenticate users with a secure token
 */
export class TokenAuthenticatorImpl<P> implements TokenAuthenticator<P> {
  private static readonly UNAUTH: UserSecurityContext<
    any
  > = UnauthenticatedContext;
  private readonly _tokenParser: TokenEncoder;
  private readonly _tokenDao: TokenDao<P>;
  private readonly _secureHash: SecureHash;

  constructor(
    tokenParser: TokenEncoder,
    tokenDao: TokenDao<P>,
    secureHash: SecureHash
  ) {
    this._tokenParser = tokenParser;
    this._tokenDao = tokenDao;
    this._secureHash = secureHash;
  }

  public async authenticateToken(
    claim: AuthTokenClaim
  ): Promise<UserSecurityContext<P>> {
    const token = claim.token;
    const tokenInfo = this._tokenParser.decode(token);
    const authToken = await this._tokenDao.getToken(tokenInfo.tokenKey);
    if (
      authToken != null &&
      (await this._secureHash.verifyHash(
        tokenInfo.tokenValue,
        authToken.hashToken
      ))
    ) {
      return {
        isAuthenticated: true,
        authClaim: claim,
        principal: authToken.user
      };
    }
    return TokenAuthenticatorImpl.UNAUTH;
  }
}