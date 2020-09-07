import { AuthClaim } from './auth-claim';
import { AuthTokenSecure } from './auth-token';

export interface SecurityContext {
    readonly isAuthenticated: boolean;
    readonly errorMessage?: string;
    readonly authClaim: AuthClaim;
}

/**
 * User based context - access according to user permissions
 */
export interface UserSecurityContext<P> extends SecurityContext {
    readonly principal: P;
}

/**
 * Action based context - permission is granted for certion actions (e.g. reset access token, reset password)
 */
export interface ActionSecurityContext<P> extends SecurityContext {
    readonly authToken: AuthTokenSecure<P>;
}
