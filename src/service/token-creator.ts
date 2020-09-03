import { Principal } from "../domain/principal";
import { AuthToken } from "../domain/auth-token";
import { UserSecurityContext } from "../domain/security-context";

/**
 * Creates auth tokens
 */
export interface TokenCreator<P> {
  /**
   * Creates a new authentication token for this user
   * @param authUser user
   */
  createAuthenticationToken(
    context: UserSecurityContext<P>
  ): Promise<AuthToken<P>>;
}
