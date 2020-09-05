import { Principal } from './principal';
import { AuthClaim } from './auth-claim';

export interface UserSecurityContext<P> {
    readonly isAuthenticated: boolean;
    readonly errorMessage?: string;
    readonly authClaim: AuthClaim;
    readonly principal: P;
}
