import { Principal } from '../domain/principal';
import { AuthToken, AuthTokenSecure } from '../domain/auth-token';
import { UserSecurityContext } from '../domain/security-context';

/**
 * Creates auth tokens
 */
export interface TokenCreator<P> {
    /**
     * Creates a new user verification token for this user
     * @param authUser user
     */
    createVerifyToken(user: P): Promise<AuthToken<P>>;

    /**
     * Creates a new access token for this user
     * @param authUser user
     */
    createAccessToken(user: P): Promise<AuthToken<P>>;

    /**
     * Creates a new reset token for an existing access token
     * @param authUser user
     */
    createRefreshToken(user: P): Promise<AuthToken<P>>;

    /**
     * Updates an existing reset token
     * @param authUser user
     */
    updateRefreshToken(currentToken: AuthTokenSecure<P>): Promise<AuthToken<P>>;

    /**
     * Creates a new reset token for this user
     * @param username user
     */
    createPasswordResetToken(user: P): Promise<AuthToken<P>>;
}
