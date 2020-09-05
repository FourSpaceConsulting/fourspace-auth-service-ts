import { UserSecurityContext } from '../domain/security-context';
import { AuthTokenClaim, AuthPasswordResetClaim } from '../domain/auth-claim';
import { TokenAuthResult } from '../domain/auth-result';

export interface TokenAuthenticator<P> {
    authenticateUserToken(claim: AuthTokenClaim): Promise<TokenAuthResult<P>>;
    authenticateResetToken(claim: AuthPasswordResetClaim): Promise<TokenAuthResult<P>>;
}
