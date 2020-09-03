import { AuthUser } from '../domain/auth-user';
import { AuthToken } from '../domain/auth-token';

/**
 * Creates auth tokens
 */
export interface TokenCreator {
  /**
   * Creates a new authentication token for this user
   * @param authUser user
   */
  createAuthenticationToken(authUser: AuthUser): Promise<AuthToken>;
}
