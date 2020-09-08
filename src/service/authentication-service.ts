import { AuthToken, AccessTokenResponse, AuthTokenSecure, TokenType } from '../domain/auth-token';
import { UserSecurityContext, ActionSecurityContext } from '../domain/security-context';
import {
    AccessTokenAuthClaim,
    PasswordAuthClaim,
    PasswordResetAuthClaim,
    RefreshAccessTokenAuthClaim,
    VerifyUserAuthClaim,
} from '../domain/auth-claim';
import { ResetRequest, ResetRequestResponse } from '../domain/reset-request';
import { RegisterRequest, RegisterResponse } from '../domain/register-request';

/**
 * General authentication service
 */
export interface AuthenticationService<P> {
    /**
     * Create a user security context from a password claim
     * @param claim
     */
    authenticatePasswordClaim(claim: PasswordAuthClaim): Promise<UserSecurityContext<P>>;

    /**
     * Create a user security context from a token claim
     * @param claim token claim
     */
    authenticateAccessTokenClaim(claim: AccessTokenAuthClaim): Promise<UserSecurityContext<P>>;

    /**
     * Create an action security context from a verify claim
     * @param claim verify claim
     */
    authenticateVerifyClaim(claim: VerifyUserAuthClaim): Promise<ActionSecurityContext<P>>;

    /**
     * Create an action security context from a refresh claim
     * @param principal principal for token
     */
    authenticateTokenRefreshClaim(claim: RefreshAccessTokenAuthClaim): Promise<ActionSecurityContext<P>>;

    /**
     * Create an action security context from a refresh claim
     * @param principal principal for token
     */
    authenticatePasswordResetClaim(claim: PasswordResetAuthClaim): Promise<ActionSecurityContext<P>>;

    /**
     * Create a new access token
     * @param principal principal for token
     */
    createAccessToken(principal: P): Promise<AccessTokenResponse>;

    /**
     * Refresh an access token
     * @param principal principal for token
     */
    refreshAccessToken(refreshToken: AuthTokenSecure<P>): Promise<AccessTokenResponse>;

    /**
     * Revoke a refresh token
     * @param principal principal for token
     */
    revokeRefreshToken(refreshToken: AuthTokenSecure<P>): Promise<boolean>;

    /**
     * Register a new user
     * @param registerRequest register info
     */
    createUserAndSendVerificationMessage(registerRequest: RegisterRequest<P>): Promise<RegisterResponse>;

    /**
     * verify new user
     * @param principal principal for token
     */
    verifyUser(principal: P): Promise<boolean>;

    /**
     * Request a password reset for a user
     * @param resetRequest reset info
     */
    requestResetPassword(resetRequest: ResetRequest): Promise<ResetRequestResponse<P>>;

    /**
     * Reset the password for a user
     * @param principal
     * @param newPassword
     */
    resetPassword(principal: P, newPassword: string): Promise<boolean>;
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
