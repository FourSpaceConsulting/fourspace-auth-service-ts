import { AuthPasswordClaim } from '../domain/auth-claim';
import { AuthResult } from '../domain/auth-result';

export interface UserAuthenticator<P> {
    authenticateUser(claim: AuthPasswordClaim): Promise<AuthResult<P>>;
}
