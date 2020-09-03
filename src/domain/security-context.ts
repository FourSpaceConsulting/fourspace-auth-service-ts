import { AuthUser } from "./auth-user";

export interface UserSecurityContext {
  readonly isAuthenticated: boolean;
  readonly principal: AuthUser;
}

export const UnauthenticatedContext: UserSecurityContext = {
  isAuthenticated: false,
  principal: null
};
