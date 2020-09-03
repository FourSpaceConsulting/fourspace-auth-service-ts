import { AuthToken } from "../domain/auth-token";
import { UserSecurityContext } from "../domain/security-context";
import { AuthTokenClaim, AuthPasswordClaim } from "../domain/auth-claim";

/**
 * General authentication service
 */
export interface AuthenticationManager<P> {
  /**
   * Create a user security context from a password claim
   * @param claim
   */
  verifyPasswordClaim(claim: AuthPasswordClaim): UserSecurityContext<P>;

  /**
   * Create a user security context from a token claim
   * @param claim token claim
   */
  verifyTokenClaim(claim: AuthTokenClaim): UserSecurityContext<P>;

  /**
   * Create a new user token
   * @param context
   */
  createUserToken(context: UserSecurityContext<P>): AuthToken<P>;

  // boolean updateUserPassword(String username, String oldPassword, String newPassword);

  // String resetUserPassword(String username);
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
 */
