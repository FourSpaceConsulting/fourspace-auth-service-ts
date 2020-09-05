import { TokenDao } from '../../dao/token-dao';
import { TokenAuthenticator } from './../token-authenticator';
import { SecureHash } from './../secure-hash';
import { TokenEncoder } from '../token-encoder';
import { AuthTokenClaim, AuthPasswordResetClaim } from '../../domain/auth-claim';
import { TokenType } from '../../domain/auth-token';
import { TokenAuthResult } from '../../domain/auth-result';
import { createFailTokenResult } from '../util';

/**
 * Authenticate users with a secure token
 */
export class TokenAuthenticatorImpl<P> implements TokenAuthenticator<P> {
    private readonly _tokenParser: TokenEncoder;
    private readonly _tokenDao: TokenDao<P>;
    private readonly _secureHash: SecureHash;

    constructor(tokenParser: TokenEncoder, tokenDao: TokenDao<P>, secureHash: SecureHash) {
        this._tokenParser = tokenParser;
        this._tokenDao = tokenDao;
        this._secureHash = secureHash;
    }

    public async authenticateUserToken(claim: AuthTokenClaim): Promise<TokenAuthResult<P>> {
        const token = claim.token;
        return this._authToken(token, TokenType.UserToken);
    }

    public async authenticateResetToken(claim: AuthPasswordResetClaim): Promise<TokenAuthResult<P>> {
        const token = claim.resetToken;
        return this._authToken(token, TokenType.ResetToken);
    }

    private async _authToken(encodedToken: string, tokenType: TokenType): Promise<TokenAuthResult<P>> {
        // decode the token and look up via the key
        const tokenInfo = this._tokenParser.decode(encodedToken);
        const authToken = await this._tokenDao.getToken(tokenInfo.tokenKey);
        // if token found and types match, then verify the hash
        if (
            authToken != null &&
            authToken.tokenType === tokenType &&
            (await this._secureHash.verifyHash(tokenInfo.tokenValue, authToken.hashToken))
        ) {
            return {
                isAuthenticated: true,
                principal: authToken.user,
                authToken,
            };
        }
        return createFailTokenResult('Failed');
    }
}
