import {
    TokenCriteriaSearchType,
    TokenSearchCriteriaByUser,
    TokenSearchCriteriaByTypeAndUser,
    TokenSearchCriteriaSingleToken,
} from './token-dao';
import { TokenType, AuthTokenSecure } from '../domain/auth-token';

/**
 * Token Dao search criteria
 * @param username
 */
export const createTokenSearchCriteriaUser = (username: string): TokenSearchCriteriaByUser => ({
    searchType: TokenCriteriaSearchType.User,
    username,
});

/**
 * Token Dao search criteria
 * @param username
 */
export const createTokenSearchCriteriaByTypeAndUser = (
    username: string,
    tokenType: TokenType
): TokenSearchCriteriaByTypeAndUser => ({
    searchType: TokenCriteriaSearchType.UserTokenType,
    username,
    tokenType,
});

/**
 * Token Dao search criteria
 * @param username
 */
export const createTokenSearchCriteriaSingleToken = <P>(
    token: AuthTokenSecure<P>
): TokenSearchCriteriaSingleToken<P> => ({
    searchType: TokenCriteriaSearchType.Token,
    token,
});
