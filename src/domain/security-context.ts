import { Principal } from "./principal";
import { AuthClaim } from "./auth-claim";

export interface UserSecurityContext<P> {
  readonly isAuthenticated: boolean;
  readonly authClaim: AuthClaim;
  readonly principal: P;
}

export const UnauthenticatedContext: UserSecurityContext<any> = {
  isAuthenticated: false,
  authClaim: null,
  principal: null
};
