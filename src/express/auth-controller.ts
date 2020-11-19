import { getActionContextToken, getUserContextPrincipal, getActionContextPrincipal } from './request-util';
import { AccessTokenResponse } from '../domain/auth-token';
import { AuthenticationService } from '../service/authentication-service';
import { RequestUserMapper } from './request-user-mapper';
import { UsernameGetter, PasswordGetter } from './validation-handlers';
import { AuthExceptionService } from './exception-service';
import { ExpressLikeRequest } from './express-interface';

/**
 * Controller for all authorisation action API requests
 */
export interface AuthController<PDTO> {
    registerUser(r: ExpressLikeRequest): Promise<boolean>;
    verifyUser(r: ExpressLikeRequest): Promise<boolean>;
    logIn(r: ExpressLikeRequest): Promise<AccessTokenResponse>;
    getAuthenticatedUser(r: ExpressLikeRequest): PDTO;
    refreshToken(r: ExpressLikeRequest): Promise<AccessTokenResponse>;
    logOut(r: ExpressLikeRequest): Promise<boolean>;
    requestPasswordReset(r: ExpressLikeRequest): Promise<boolean>;
    performPasswordReset(r: ExpressLikeRequest): Promise<boolean>;
}

type UserMapper<P, PDTO> = (p: P) => PDTO;

/**
 * Implementation using the authentication service
 */
export class AuthControllerImpl<P, PDTO> implements AuthController<PDTO> {
    private readonly _authenticationService: AuthenticationService<P>;
    private readonly _requestUserMapper: RequestUserMapper<P, PDTO>;
    private readonly _exceptionService: AuthExceptionService;

    constructor(
        authenticationService: AuthenticationService<P>,
        requestUserMapper: RequestUserMapper<P, PDTO>,
        exceptionService: AuthExceptionService
    ) {
        this._authenticationService = authenticationService;
        this._requestUserMapper = requestUserMapper;
        this._exceptionService = exceptionService;
    }

    public async registerUser(r: ExpressLikeRequest): Promise<boolean> {
        // validate the request body
        if (!(await this._requestUserMapper.validateNewUser(r.body))) {
            this._exceptionService.throwBadRequest('Invalid user');
        }
        // create the user
        const newPrincipal = this._requestUserMapper.createNewUser(r.body);
        const password = PasswordGetter(r);
        //
        if (newPrincipal == null) this._exceptionService.throwBadRequest('Unable to register user');
        // register the user
        const response = await this._authenticationService.createUserAndSendVerificationMessage({
            newPrincipal,
            password,
        });
        return response.isSuccess;
    }

    public async verifyUser(r: ExpressLikeRequest): Promise<boolean> {
        // get the principal from the security context
        const principal = getActionContextPrincipal<P>(r, this._exceptionService);
        // delete this token - verification can only happen once
        // verify the user
        const verify = await this._authenticationService.verifyUser(principal);
        return verify;
    }

    public async logIn(r: ExpressLikeRequest): Promise<AccessTokenResponse> {
        // get the principal from the security context
        const principal = getUserContextPrincipal<P>(r, this._exceptionService);
        // create the tokens for this principal
        return this._authenticationService.createAccessToken(principal);
    }

    public getAuthenticatedUser(r: ExpressLikeRequest): PDTO {
        // get the principal from the security context
        const principal = getUserContextPrincipal<P>(r, this._exceptionService);
        // map to the dto
        return this._requestUserMapper.mapToDto(principal);
    }

    public refreshToken(r: ExpressLikeRequest): Promise<AccessTokenResponse> {
        // get the refresh token from the security context
        const token = getActionContextToken<P>(r, this._exceptionService);
        // refresh the access token
        return this._authenticationService.refreshAccessToken(token);
    }

    public logOut(r: ExpressLikeRequest): Promise<boolean> {
        // get the refresh token from the security context
        const token = getActionContextToken<P>(r, this._exceptionService);
        // revoke the token
        return this._authenticationService.revokeRefreshToken(token);
    }

    public async requestPasswordReset(r: ExpressLikeRequest): Promise<boolean> {
        // get the username for the request
        const username = UsernameGetter(r);
        // get the origin of the request
        const origin = 'unkn';
        // request a reset
        const response = await this._authenticationService.requestResetPassword({ username, origin });
        return response.success;
    }

    public async performPasswordReset(r: ExpressLikeRequest): Promise<boolean> {
        // get the principal from the security context
        const principal = getActionContextPrincipal<P>(r, this._exceptionService);
        // get the password for the request
        const password = PasswordGetter(r);
        // delete this token - password reset should only be allowed once
        // reset the password
        const response = await this._authenticationService.resetPassword(principal, password);
        // return the response
        return response;
    }
}
