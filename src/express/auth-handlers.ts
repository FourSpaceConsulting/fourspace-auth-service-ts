import { ExpressLikeRequestHandler, ExpressLikeRequest } from './express-interface';
import { AuthenticationService } from '../service/authentication-service';
import {
    createPasswordAuthClaim,
    createAccessTokenAuthClaim,
    createPasswordResetAuthClaim,
    createRefreshAccessTokenAuthClaim,
    createVerifyUserAuthClaim,
} from '../domain/auth-claim';
import { AuthExceptionService } from './exception-service';
import { UsernameGetter, PasswordGetter } from './validation-handlers';
import { getAuthorizationHeader } from './request-util';

/**
 * These are the express handlers for authenticating various claims
 */
export interface AuthHandlers {
    readonly authenticatePasswordClaim: ExpressLikeRequestHandler;
    readonly authenticateAccessTokenClaim: ExpressLikeRequestHandler;
    readonly authenticateVerifyClaim: ExpressLikeRequestHandler;
    readonly authenticateTokenRefreshClaim: ExpressLikeRequestHandler;
    readonly authenticatePasswordResetClaim: ExpressLikeRequestHandler;
}

/**
 * Handler implementation
 */
export class AuthHandlerImpl<P> implements AuthHandlers {
    private _authenticatePasswordClaim: ExpressLikeRequestHandler;
    private _authenticateAccessTokenClaim: ExpressLikeRequestHandler;
    private _authenticateVerifyClaim: ExpressLikeRequestHandler;
    private _authenticateTokenRefreshClaim: ExpressLikeRequestHandler;
    private _authenticatePasswordResetClaim: ExpressLikeRequestHandler;

    constructor(service: AuthenticationService<P>, ex: AuthExceptionService) {
        this._setAuthenticatePasswordClaimHandler(service, ex);
        this._setAuthenticateAccessTokenClaimHandler(service, ex);
        this._setAuthenticateTokenRefreshClaimHandler(service, ex);
        this._setAuthenticatePasswordResetClaimHandler(service, ex);
        this._setAuthenticateVerifyClaimHandler(service, ex);
    }

    //#region --- Handler Getters

    /**
     * Getter authenticatePasswordClaim
     * @return {ExpressLikeRequestHandler}
     */
    public get authenticatePasswordClaim(): ExpressLikeRequestHandler {
        return this._authenticatePasswordClaim;
    }

    /**
     * Getter authenticateAccessTokenClaim
     * @return {ExpressLikeRequestHandler}
     */
    public get authenticateAccessTokenClaim(): ExpressLikeRequestHandler {
        return this._authenticateAccessTokenClaim;
    }

    /**
     * Getter authenticateVerifyClaim
     * @return {ExpressLikeRequestHandler}
     */
    public get authenticateVerifyClaim(): ExpressLikeRequestHandler {
        return this._authenticateVerifyClaim;
    }

    /**
     * Getter authenticateTokenRefreshClaim
     * @return {ExpressLikeRequestHandler}
     */
    public get authenticateTokenRefreshClaim(): ExpressLikeRequestHandler {
        return this._authenticateTokenRefreshClaim;
    }

    /**
     * Getter authenticatePasswordResetClaim
     * @return {ExpressLikeRequestHandler}
     */
    public get authenticatePasswordResetClaim(): ExpressLikeRequestHandler {
        return this._authenticatePasswordResetClaim;
    }

    //#endregion
    //#region --- Create the handlers

    private _setAuthenticatePasswordClaimHandler(service: AuthenticationService<P>, ex: AuthExceptionService) {
        this._authenticatePasswordClaim = async (req, _, next) => {
            // authenticate
            const claim = createPasswordAuthClaim(UsernameGetter(req), PasswordGetter(req));
            req.securityContext = await service.authenticatePasswordClaim(claim);
            // advance if authenticated
            if (!throwIfNotAuthenticated(req, ex)) {
                next();
            }
        };
    }

    private _setAuthenticateAccessTokenClaimHandler(service: AuthenticationService<P>, ex: AuthExceptionService) {
        this._authenticateAccessTokenClaim = async (req, _, next) => {
            // authenticate
            const claim = createAccessTokenAuthClaim(getAuthorizationHeader(req));
            req.securityContext = await service.authenticateAccessTokenClaim(claim);
            // advance
            if (!throwIfNotAuthenticated(req, ex)) {
                next();
            }
        };
    }

    private _setAuthenticatePasswordResetClaimHandler(service: AuthenticationService<P>, ex: AuthExceptionService) {
        this._authenticatePasswordResetClaim = async (req, _, next) => {
            // authenticate
            const claim = createPasswordResetAuthClaim(getAuthorizationHeader(req));
            req.securityContext = await service.authenticatePasswordResetClaim(claim);
            // advance
            if (!throwIfNotAuthenticated(req, ex)) {
                next();
            }
        };
    }

    private _setAuthenticateTokenRefreshClaimHandler(service: AuthenticationService<P>, ex: AuthExceptionService) {
        this._authenticateTokenRefreshClaim = async (req, _, next) => {
            // authenticate
            const claim = createRefreshAccessTokenAuthClaim(getAuthorizationHeader(req));
            req.securityContext = await service.authenticateTokenRefreshClaim(claim);
            // advance
            if (!throwIfNotAuthenticated(req, ex)) {
                next();
            }
        };
    }

    private _setAuthenticateVerifyClaimHandler(service: AuthenticationService<P>, ex: AuthExceptionService) {
        this._authenticateVerifyClaim = async (req, _, next) => {
            // authenticate
            const claim = createVerifyUserAuthClaim(getAuthorizationHeader(req));
            req.securityContext = await service.authenticateVerifyClaim(claim);
            // advance
            if (!throwIfNotAuthenticated(req, ex)) {
                next();
            }
        };
    }

    //#endregion
}

function throwIfNotAuthenticated(req: ExpressLikeRequest, ex: AuthExceptionService): boolean {
    return !(req.securityContext.isAuthenticated || ex.throwUnauthenticated());
}
