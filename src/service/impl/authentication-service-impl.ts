import { AuthenticationService } from '../authentication-service';
import { PasswordAuthClaim, AccessTokenAuthClaim, PasswordResetAuthClaim, RefreshAccessTokenAuthClaim, VerifyUserAuthClaim } from '../../domain/auth-claim';
import { UserSecurityContext, ActionSecurityContext } from '../../domain/security-context';
import { UserAuthenticator } from '../user-authenticator';
import { TokenCreator } from '../token-creator';
import { TokenAuthenticator } from '../token-authenticator';
import { TokenEncoder } from '../token-encoder';
import { TokenDao } from '../../dao/token-dao';
import { ResetRequest, ResetRequestResponse } from '../../domain/reset-request';
import { getTokenInfo } from '../util';
import { PrincipalDao } from '../../dao/principal-dao';
import { Principal } from '../../domain/principal';
import { SecureHash } from '../secure-hash';
import { RegisterRequest, RegisterResponse } from '../../domain/register-request';
import { ActionMessage, ActionType } from '../../domain/action-message';
import { AccessTokenResponse, AuthToken, AuthTokenSecure } from '../../domain/auth-token';
import { ActionMessageService } from '../../actions/action-message-service';

/**
 * Implementation of authentication service
 */
export class AuthenticationServiceImpl<P extends Principal> implements AuthenticationService<P> {
    private _userAuthenticator: UserAuthenticator<P>;
    private _tokenAuthenticator: TokenAuthenticator<P>;
    private _tokenCreator: TokenCreator<P>;
    private _tokenEncoder: TokenEncoder;
    private _tokenDao: TokenDao<P>;
    private _principalDao: PrincipalDao<P>;
    private _secureHash: SecureHash;
    private _actionMessageService: ActionMessageService<P>;

    constructor(
        userAuthenticator: UserAuthenticator<P>,
        tokenAuthenticator: TokenAuthenticator<P>,
        tokenCreator: TokenCreator<P>,
        tokenEncoder: TokenEncoder,
        tokenDao: TokenDao<P>,
        principalDao: PrincipalDao<P>,
        secureHash: SecureHash,
        actionMessageService: ActionMessageService<P>
    ) {
        this._userAuthenticator = userAuthenticator;
        this._tokenAuthenticator = tokenAuthenticator;
        this._tokenCreator = tokenCreator;
        this._tokenEncoder = tokenEncoder;
        this._tokenDao = tokenDao;
        this._principalDao = principalDao;
        this._secureHash = secureHash;
        this._actionMessageService = actionMessageService;
    }

    public async authenticateVerifyClaim(claim: VerifyUserAuthClaim): Promise<ActionSecurityContext<P>> {
        // authenticate user claim
        const result = await this._tokenAuthenticator.authenticateVerifyToken(claim);
        // return security context
        return {
            isAuthenticated: result.isAuthenticated,
            errorMessage: result.errorMessage,
            authClaim: claim,
            authToken: result.authToken
        };
    }

    public async authenticatePasswordClaim(claim: PasswordAuthClaim): Promise<UserSecurityContext<P>> {
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

    public async authenticateAccessTokenClaim(claim: AccessTokenAuthClaim): Promise<UserSecurityContext<P>> {
        // authenticate token claim
        const result = await this._tokenAuthenticator.authenticateAccessToken(claim);
        // return security context
        return {
            isAuthenticated: result.isAuthenticated,
            principal: result.principal,
            errorMessage: result.errorMessage,
            authClaim: claim,
        };
    }

    public async authenticateTokenRefreshClaim(claim: RefreshAccessTokenAuthClaim): Promise<ActionSecurityContext<P>> {
        // authenticate token claim
        const result = await this._tokenAuthenticator.authenticateRefreshToken(claim);
        // return security context
        return {
            isAuthenticated: result.isAuthenticated,
            errorMessage: result.errorMessage,
            authClaim: claim,
            authToken: result.authToken
        };
    }

    public async authenticatePasswordResetClaim(claim: PasswordResetAuthClaim): Promise<ActionSecurityContext<P>> {
        // authenticate token claim
        const result = await this._tokenAuthenticator.authenticatePasswordResetToken(claim);
        // return security context
        return {
            isAuthenticated: result.isAuthenticated,
            errorMessage: result.errorMessage,
            authClaim: claim,
            authToken: result.authToken
        };
    }


    public async createAccessToken(principal: P): Promise<AccessTokenResponse> {
        // create and save new token
        const accessToken = await this._saveToken(await this._tokenCreator.createAccessToken(principal));
        // persist
        const refreshToken = await this._saveToken(await this._tokenCreator.createRefreshToken(principal));
        // encode and return
        return {
            accessToken: this._tokenEncoder.encode(getTokenInfo(accessToken)),
            refreshToken: this._tokenEncoder.encode(getTokenInfo(refreshToken))
        }
    }

    public async refreshAccessToken(refreshToken: AuthTokenSecure<P>): Promise<AccessTokenResponse> {
        const newRefreshToken = await this._saveToken(await this._tokenCreator.updateRefreshToken(refreshToken));
        const accessToken = await this._saveToken(await this._tokenCreator.createAccessToken(refreshToken.principal));
        return {
            accessToken: this._tokenEncoder.encode(getTokenInfo(accessToken)),
            refreshToken: this._tokenEncoder.encode(getTokenInfo(newRefreshToken))
        };
    }

    public async registerUser(registerRequest: RegisterRequest<P>): Promise<RegisterResponse> {
        // set the encrypted password
        const principal = registerRequest.newPrincipal;
        principal.encryptedPassword = await this._secureHash.createHash(registerRequest.password);
        // save the principal
        const savedPrincipal = await this._principalDao.savePrincipal(principal);
        // create new token
        const verifyToken = await this._saveToken(await this._tokenCreator.createVerifyToken(principal));
        // encode
        const encodedToken = this._tokenEncoder.encode(getTokenInfo(verifyToken));
        // send action message
        const action: ActionMessage<P> = { principal: savedPrincipal, actionType: ActionType.Verify, actionToken: encodedToken };
        const response = await this._actionMessageService.sendActionMessage(action);
        // return response
        return {
            isSuccess: response.isSuccess,
            message: response.errorMessage,
            encodedToken,
        };
    }

    public async requestResetPassword(resetRequest: ResetRequest): Promise<ResetRequestResponse<P>> {
        // get user
        const principal = await this._principalDao.getPrincipal(resetRequest.username);
        if (principal != null) {
            // create and persist new token
            const token = await this._saveToken(await this._tokenCreator.createPasswordResetToken(principal));
            // encode and return
            const encodedToken = this._tokenEncoder.encode(getTokenInfo(token));
            // send action message
            const action: ActionMessage<P> = { principal: principal, actionType: ActionType.PasswordReset, actionToken: encodedToken };
            const response = await this._actionMessageService.sendActionMessage(action);
            // return response
            return {
                success: true,
                origin: resetRequest.origin,
                principal,
                encodedToken,
            };
        }
        return {
            success: false,
            origin: resetRequest.origin,
            principal: null,
            encodedToken: null
        };
    }

    public async resetPassword(principal: P, newPassword: string): Promise<boolean> {
        principal.encryptedPassword = await this._secureHash.createHash(newPassword);
        // save the principal
        this._principalDao.updatePrincipal(principal);
        // return success
        return true;
    }

    /**
     * Set verified flag to true and save user
     * @param principal 
     */
    public async verifyUser(principal: P): Promise<boolean> {
        principal.isVerified = true;
        const saved = await this._principalDao.updatePrincipal(principal);
        return saved.isVerified;
    }

    /**
     * Save secure part of the token
     * return the auth token (with any values updated by the save action e.g. key)
     * @param token auth token
     */
    private async _saveToken(token: AuthToken<P>): Promise<AuthToken<P>> {
        // persist
        const secureToken = await this._tokenDao.saveToken(token);
        // merge token, as the key may only be set on persistence
        return { ...token, ...secureToken };
    }

}
