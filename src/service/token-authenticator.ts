import {
    AccessTokenAuthClaim,
    PasswordResetAuthClaim,
    RefreshAccessTokenAuthClaim,
    VerifyUserAuthClaim,
} from '../domain/auth-claim';
import { TokenAuthResult } from '../domain/auth-result';

export interface TokenAuthenticator<P> {
    authenticateAccessToken(claim: AccessTokenAuthClaim): Promise<TokenAuthResult<P>>;
    authenticateRefreshToken(claim: RefreshAccessTokenAuthClaim): Promise<TokenAuthResult<P>>;
    authenticateVerifyToken(claim: VerifyUserAuthClaim): Promise<TokenAuthResult<P>>;
    authenticatePasswordResetToken(claim: PasswordResetAuthClaim): Promise<TokenAuthResult<P>>;
}
