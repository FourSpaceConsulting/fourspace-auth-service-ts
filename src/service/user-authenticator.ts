import { UserSecurityContext } from "../domain/security-context";
import { AuthPasswordClaim } from "../domain/auth-claim";

export interface UserAuthenticator<P> {
  authenticateUser(claim: AuthPasswordClaim): Promise<UserSecurityContext<P>>;
}
