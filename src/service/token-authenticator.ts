import { UserSecurityContext } from "../domain/security-context";
import { AuthTokenClaim } from "../domain/auth-claim";

export interface TokenAuthenticator<P> {
  authenticateToken(claim: AuthTokenClaim): Promise<UserSecurityContext<P>>;
}
