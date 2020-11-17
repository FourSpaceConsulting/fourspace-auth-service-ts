import { AuthClaim } from './auth-claim';
import { AuthTokenSecure } from './auth-token';

export enum SecurityContextType {
    User,
    Action,
}

export interface SecurityContextCommon {
    readonly isAuthenticated: boolean;
    readonly errorMessage?: string;
    readonly authClaim: AuthClaim;
}

/**
 * User based context - access according to user permissions
 */
export interface UserSecurityContext<P> extends SecurityContextCommon {
    readonly contextType: SecurityContextType.User;
    readonly principal: P;
}

/**
 * Action based context - permission is granted for certion actions (e.g. reset access token, reset password)
 */
export interface ActionSecurityContext<P> extends SecurityContextCommon {
    readonly contextType: SecurityContextType.Action;
    readonly authToken: AuthTokenSecure<P>;
}

/**
 * All types
 */
export type SecurityContext<P> = UserSecurityContext<P> | ActionSecurityContext<P>;
