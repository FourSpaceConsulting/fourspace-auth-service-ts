import { UserSecurityContext } from "../domain/security-context";

export interface TokenAuthenticator {
  authenticateToken(token: string): Promise<UserSecurityContext>;
}
