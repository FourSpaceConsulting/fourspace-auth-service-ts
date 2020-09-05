import { AuthTokenSecure } from './auth-token';

export interface AuthResult<P> {
    readonly isAuthenticated: boolean;
    readonly errorMessage?: string;
    readonly principal: P;
}
export interface TokenAuthResult<P> extends AuthResult<P> {
    authToken: AuthTokenSecure<P>;
}
