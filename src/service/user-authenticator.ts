import { PasswordAuthClaim } from '../domain/auth-claim';
import { AuthResult } from '../domain/auth-result';

export interface UserAuthenticator<P> {
    authenticateUser(claim: PasswordAuthClaim): Promise<AuthResult<P>>;
}
