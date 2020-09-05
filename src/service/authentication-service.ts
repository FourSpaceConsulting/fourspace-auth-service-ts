import { AuthToken } from '../domain/auth-token';
import { UserSecurityContext } from '../domain/security-context';
import { AuthTokenClaim, AuthPasswordClaim, AuthPasswordResetClaim } from '../domain/auth-claim';
import { ResetRequest, ResetRequestResponse } from '../domain/reset-request';
import { RegisterRequest, RegisterResponse } from '../domain/register-request';

/**
 * General authentication service
 */
export interface AuthenticationService<P> {
    /**
     * Register a new user
     * @param registerRequest register info
     */
    registerUser(registerRequest: RegisterRequest<P>): Promise<RegisterResponse>;

    /**
     * Create a user security context from a password claim
     * @param claim
     */
    verifyPasswordClaim(claim: AuthPasswordClaim): Promise<UserSecurityContext<P>>;

    /**
     * Request a password reset for a user
     * @param resetRequest reset info
     */
    requestResetPassword(resetRequest: ResetRequest): Promise<ResetRequestResponse<P>>;

    /**
     * reset the password
     * @param claim reset claim
     */
    resetPassword(claim: AuthPasswordResetClaim, newPassword: string): Promise<boolean>;

    /**
     * Create a user security context from a token claim
     * @param claim token claim
     */
    verifyTokenClaim(claim: AuthTokenClaim): Promise<UserSecurityContext<P>>;

    /**
     * Create a new user token
     * @param principal principal for token
     */
    createUserToken(principal: P): Promise<string>;
}

/**
 * Register
 * 1) User supplies email and password
 * 2) email link to verify user
 * 3) on click, user is verified and can log in with password
 * 4) user logs in - create User Token and return
 *
 * Log in
 * 1) User supplies email and password
 * 2) create token and return to user
 *
 * Standard API call
 * 1) method call with token attached
 * 2) verify token, return security context
 * 3) if all good, proceed with method
 *
 * Reset password
 * 1) call to reset made (auth not necessary)
 * 2) email link to user email (containing timestamp reset token)
 * 3) on click, page for reset is loaded, on submit api call made with reset token
 * 4) if reset token matches within timestamp, then reset password
 */
