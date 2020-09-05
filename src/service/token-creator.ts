import { Principal } from '../domain/principal';
import { AuthToken } from '../domain/auth-token';
import { UserSecurityContext } from '../domain/security-context';

/**
 * Creates auth tokens
 */
export interface TokenCreator<P> {
    /**
     * Creates a new user authentication token for this user
     * @param authUser user
     */
    createAuthenticationToken(user: P): Promise<AuthToken<P>>;

    /**
     * Creates a new reset token for this user
     * @param username user
     */
    createPasswordResetToken(user: P): Promise<AuthToken<P>>;
}
