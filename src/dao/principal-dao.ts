import { AuthToken, AuthTokenSecure } from "../domain/auth-token";

/**
 * Data access object for Principal objects
 */
export interface PrincipalDao<P> {
  /**
   * get auth token given the unique id
   * @param key unique id
   */
  getPrincipal(key: string): Promise<P>;
}
