import { UserAuthenticator } from "../user-authenticator";
import { AuthPasswordClaim } from "../../domain/auth-claim";
import {
  UserSecurityContext,
  UnauthenticatedContext
} from "../../domain/security-context";
import { PrincipalDao } from "../../dao/principal-dao";
import { Principal } from "../../domain/principal";
import { SecureHash } from "../secure-hash";

/**
 * User authenticator for password claims
 */
export class UserAuthenticatorImpl<P extends Principal>
  implements UserAuthenticator<P> {
  private readonly _principalDao: PrincipalDao<P>;
  private readonly _secureHash: SecureHash;

  constructor(principalDao: PrincipalDao<P>, secureHash: SecureHash) {
    this._principalDao = principalDao;
    this._secureHash = secureHash;
  }

  public async authenticateUser(
    claim: AuthPasswordClaim
  ): Promise<UserSecurityContext<P>> {
    const user = await this._principalDao.getPrincipal(claim.user);
    if (
      user != null &&
      (await this._secureHash.verifyHash(claim.password, user.passwordHash))
    ) {
      return {
        isAuthenticated: true,
        authClaim: claim,
        principal: user
      };
    }
    return UnauthenticatedContext;
  }
}