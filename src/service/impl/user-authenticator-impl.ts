import { UserAuthenticator } from '../user-authenticator';
import { PasswordAuthClaim } from '../../domain/auth-claim';
import { PrincipalDao } from '../../dao/principal-dao';
import { Principal } from '../../domain/principal';
import { SecureHash } from '../secure-hash';
import { AuthResult } from '../../domain/auth-result';
import { createFailResult } from '../util';

/**
 * User authenticator for password claims
 */
export class UserAuthenticatorImpl<P extends Principal> implements UserAuthenticator<P> {
    private readonly _principalDao: PrincipalDao<P>;
    private readonly _secureHash: SecureHash;

    constructor(principalDao: PrincipalDao<P>, secureHash: SecureHash) {
        this._principalDao = principalDao;
        this._secureHash = secureHash;
    }

    public async authenticateUser(claim: PasswordAuthClaim): Promise<AuthResult<P>> {
        const user = await this._principalDao.getPrincipal(claim.user);
        if (
            user != null &&
            user.isVerified &&
            (await this._secureHash.verifyHash(claim.password, user.encryptedPassword))
        ) {
            return {
                isAuthenticated: true,
                principal: user,
            };
        }
        return createFailResult('Failed');
    }
}
