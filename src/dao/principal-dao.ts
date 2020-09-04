import { AuthToken, AuthTokenSecure } from "../domain/auth-token";

/**
 * Data access object for Principal objects
 */
export interface PrincipalDao<P> {
  /**
   * get auth token given the unique id
   * @param username unique id
   */
  getPrincipal(username: string): Promise<P>;
}
