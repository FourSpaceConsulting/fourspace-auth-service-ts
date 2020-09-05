import { AuthToken, AuthTokenSecure } from '../domain/auth-token';

/**
 * Data access object for AuthToken objects
 */
export interface TokenDao<P> {
    /**
     * get auth token given the unique id
     * @param key unique id
     */
    getToken(key: string): Promise<AuthTokenSecure<P>>;

    /**
     * save the auth token
     * @param token token
     */
    saveToken(token: AuthTokenSecure<P>): Promise<AuthTokenSecure<P>>;
}
