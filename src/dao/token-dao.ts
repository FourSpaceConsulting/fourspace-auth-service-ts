import { AuthTokenSecure, TokenType } from '../domain/auth-token';

/**
 * Possible ways of searching for tokens
 */
export enum TokenCriteriaSearchType {
    Token,
    UserTokenType,
    User,
}
export interface TokenSearchCriteriaSingleToken<P> {
    readonly searchType: TokenCriteriaSearchType.Token;
    readonly token: AuthTokenSecure<P>;
}
export interface TokenSearchCriteriaByUser {
    readonly searchType: TokenCriteriaSearchType.User;
    readonly username: string;
}
export interface TokenSearchCriteriaByTypeAndUser {
    readonly searchType: TokenCriteriaSearchType.UserTokenType;
    readonly username: string;
    readonly tokenType: TokenType;
}
export type SearchCriteria<P> =
    | TokenSearchCriteriaSingleToken<P>
    | TokenSearchCriteriaByTypeAndUser
    | TokenSearchCriteriaByUser;

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
     * save a new auth token
     * @param token token
     */
    saveToken(token: AuthTokenSecure<P>): Promise<AuthTokenSecure<P>>;

    /**
     * update an existing auth token
     * @param token token
     */
    updateToken(token: AuthTokenSecure<P>): Promise<AuthTokenSecure<P>>;

    /**
     * delete the auth token
     * @param token token
     */
    deleteTokens(token: SearchCriteria<P>): Promise<void>;
}
