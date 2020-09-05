import { AuthenticationService } from '../authentication-service';
import { AuthPasswordClaim, AuthTokenClaim, AuthPasswordResetClaim } from '../../domain/auth-claim';
import { UserSecurityContext } from '../../domain/security-context';
import { UserAuthenticator } from '../user-authenticator';
import { TokenCreator } from '../token-creator';
import { TokenAuthenticator } from '../token-authenticator';
import { TokenEncoder } from '../token-encoder';
import { TokenDao } from '../../dao/token-dao';
import { ResetRequest, ResetRequestResponse } from '../../domain/reset-request';
import { getTokenInfo, createFailTokenResult } from '../util';
import { PrincipalDao } from '../../dao/principal-dao';
import { Principal } from '../../domain/principal';
import { SecureHash } from '../secure-hash';
import { RegisterRequest } from '../../domain/register-request';

export class AuthenticationServiceImpl<P extends Principal> implements AuthenticationService<P> {
    private _userAuthenticator: UserAuthenticator<P>;
    private _tokenAuthenticator: TokenAuthenticator<P>;
    private _tokenCreator: TokenCreator<P>;
    private _tokenEncoder: TokenEncoder;
    private _tokenDao: TokenDao<P>;
    private _principalDao: PrincipalDao<P>;
    private _secureHash: SecureHash;

    constructor(
        userAuthenticator: UserAuthenticator<P>,
        tokenAuthenticator: TokenAuthenticator<P>,
        tokenCreator: TokenCreator<P>,
        tokenEncoder: TokenEncoder,
        tokenDao: TokenDao<P>,
        principalDao: PrincipalDao<P>,
        secureHash: SecureHash
    ) {
        this._userAuthenticator = userAuthenticator;
        this._tokenAuthenticator = tokenAuthenticator;
        this._tokenCreator = tokenCreator;
        this._tokenEncoder = tokenEncoder;
        this._tokenDao = tokenDao;
        this._principalDao = principalDao;
        this._secureHash = secureHash;
    }

    public registerUser(
        registerRequest: RegisterRequest<P>
    ): Promise<import('../../domain/register-request').RegisterResponse> {
        throw new Error('Method not implemented.');
    }

    public async verifyPasswordClaim(claim: AuthPasswordClaim): Promise<UserSecurityContext<P>> {
        // authenticate user claim
        const result = await this._userAuthenticator.authenticateUser(claim);
        // return security context
        return {
            isAuthenticated: result.isAuthenticated,
            principal: result.principal,
            errorMessage: result.errorMessage,
            authClaim: claim,
        };
    }

    public async verifyTokenClaim(claim: AuthTokenClaim): Promise<UserSecurityContext<P>> {
        // authenticate token claim
        const result = await this._tokenAuthenticator.authenticateUserToken(claim);
        // return security context
        return {
            isAuthenticated: result.isAuthenticated,
            principal: result.principal,
            errorMessage: result.errorMessage,
            authClaim: claim,
        };
    }

    public async createUserToken(principal: P): Promise<string> {
        // create new token
        const token = await this._tokenCreator.createAuthenticationToken(principal);
        // persist
        const savedToken = await this._tokenDao.saveToken(token);
        // merge token, as the key may only be set on persistence
        const mergedToken = { ...token, key: savedToken.key };
        // encode and return
        return this._tokenEncoder.encode(getTokenInfo(mergedToken));
    }

    public async requestResetPassword(resetRequest: ResetRequest): Promise<ResetRequestResponse<P>> {
        // get user
        const principal = await this._principalDao.getPrincipal(resetRequest.username);
        if (principal != null) {
            // create new token
            const token = await this._tokenCreator.createPasswordResetToken(principal);
            // persist
            const savedToken = await this._tokenDao.saveToken(token);
            // merge token, as the key may only be set on persistence
            const mergedToken = { ...token, key: savedToken.key };
            // encode and return
            const encodedToken = this._tokenEncoder.encode(getTokenInfo(mergedToken));
            // return response
            return {
                success: true,
                origin: resetRequest.origin,
                principal,
                encodedToken,
            };
        }
    }

    public async resetPassword(claim: AuthPasswordResetClaim, newPassword: string): Promise<boolean> {
        // authenticate token claim
        const result = await this._tokenAuthenticator.authenticateResetToken(claim);
        // if authentic claim, reset password
        if (result.isAuthenticated) {
            // set the encrypted password
            const principal = result.principal;
            principal.encryptedPassword = await this._secureHash.createHash(newPassword);
            // save the principal
            this._principalDao.savePrincipal(principal);
            // return success
            return true;
        }
        return false;
    }
}
