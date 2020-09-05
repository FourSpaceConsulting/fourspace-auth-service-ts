import moment from 'moment';
import { AuthToken } from '../domain/auth-token';
import { TokenInfo } from '../domain/token-info';
import { TokenAuthResult, AuthResult } from '../domain/auth-result';
import { UserSecurityContext } from '../domain/security-context';
import { AuthClaim } from '../domain/auth-claim';

export const getTokenInfo = (t: AuthToken<any>): TokenInfo => ({
    tokenKey: t.key,
    tokenValue: t.plainToken,
    expire: moment(t.created).unix(),
});

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

export const createUnauthenticatedContext = <P>(
    errorMessage: string,
    authClaim: AuthClaim
): UserSecurityContext<any> => ({
    isAuthenticated: false,
    principal: null,
    errorMessage,
    authClaim,
});
