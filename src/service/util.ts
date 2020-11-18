import moment from 'moment';
import { AuthToken } from '../domain/auth-token';
import { TokenInfo } from '../domain/token-info';
import { TokenAuthResult, AuthResult } from '../domain/auth-result';
import { UserSecurityContext } from '../domain/security-context';
import { AuthClaim } from '../domain/auth-claim';
import { ActionType } from '../domain/action-message';
import { TokenSearchCriteriaByUser, TokenCriteriaSearchType } from '../dao/token-dao';

/**
 * Create token info object from auth token.
 * This is used to create encoded tokens for clients
 * @param t token
 */
export const getTokenInfo = (t: AuthToken<any>): TokenInfo => ({
    tokenKey: t.key,
    tokenValue: t.plainToken,
    expire: moment(t.expiry).unix(),
});

/**
 * Get description for action types
 * @param m
 */
export const getActionTypeName = (m: ActionType): string => {
    switch (m) {
        case ActionType.Verify:
            return 'VerifyUser';
        case ActionType.PasswordReset:
            return 'PasswordReset';
        default:
            return 'Unkown';
    }
};

export const createFailTokenResult = <P>(errorMessage: string): TokenAuthResult<P> => ({
    errorMessage,
    isAuthenticated: false,
    principal: null,
    authToken: null,
});

export const createFailResult = <P>(errorMessage: string): AuthResult<P> => ({
    errorMessage,
    isAuthenticated: false,
    principal: null,
});
