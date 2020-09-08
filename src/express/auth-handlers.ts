import { ExpressLikeRouteHandler, ExpressLikeRequest, GetAuthorizationHeader } from './express-util';
import { AuthenticationService } from '../service/authentication-service';
import {
    createPasswordAuthClaim,
    createAccessTokenAuthClaim,
    createPasswordResetAuthClaim,
    createRefreshAccessTokenAuthClaim,
    createVerifyUserAuthClaim,
} from '../domain/auth-claim';
import { ExceptionService } from './exception-service';
import { UsernameGetter, PasswordGetter } from './validation-handlers';

/**
 * These are the express handlers for authenticating various claims
 */
export interface AuthHandlers {
    readonly authenticatePasswordClaim: ExpressLikeRouteHandler;
    readonly authenticateAccessTokenClaim: ExpressLikeRouteHandler;
    readonly authenticateVerifyClaim: ExpressLikeRouteHandler;
    readonly authenticateTokenRefreshClaim: ExpressLikeRouteHandler;
    readonly authenticatePasswordResetClaim: ExpressLikeRouteHandler;
}

/**
 * Handler implementation
 */
export class AuthHandlerImpl<P> implements AuthHandlers {
    private _authenticatePasswordClaim: ExpressLikeRouteHandler;
    private _authenticateAccessTokenClaim: ExpressLikeRouteHandler;
    private _authenticateVerifyClaim: ExpressLikeRouteHandler;
    private _authenticateTokenRefreshClaim: ExpressLikeRouteHandler;
    private _authenticatePasswordResetClaim: ExpressLikeRouteHandler;

    constructor(service: AuthenticationService<P>, ex: ExceptionService) {
        this._setAuthenticatePasswordClaimHandler(service, ex);
        this._setAuthenticateAccessTokenClaimHandler(service, ex);
        this._setAuthenticateTokenRefreshClaimHandler(service, ex);
        this._setAuthenticatePasswordResetClaimHandler(service, ex);
        this._setAuthenticateVerifyClaimHandler(service, ex);
    }

    //#region --- Handler Getters

    /**
     * Getter authenticatePasswordClaim
     * @return {ExpressLikeRouteHandler}
     */
    public get authenticatePasswordClaim(): ExpressLikeRouteHandler {
        return this._authenticatePasswordClaim;
    }

    /**
     * Getter authenticateAccessTokenClaim
     * @return {ExpressLikeRouteHandler}
     */
    public get authenticateAccessTokenClaim(): ExpressLikeRouteHandler {
        return this._authenticateAccessTokenClaim;
    }

    /**
     * Getter authenticateVerifyClaim
     * @return {ExpressLikeRouteHandler}
     */
    public get authenticateVerifyClaim(): ExpressLikeRouteHandler {
        return this._authenticateVerifyClaim;
    }

    /**
     * Getter authenticateTokenRefreshClaim
     * @return {ExpressLikeRouteHandler}
     */
    public get authenticateTokenRefreshClaim(): ExpressLikeRouteHandler {
        return this._authenticateTokenRefreshClaim;
    }

    /**
     * Getter authenticatePasswordResetClaim
     * @return {ExpressLikeRouteHandler}
     */
    public get authenticatePasswordResetClaim(): ExpressLikeRouteHandler {
        return this._authenticatePasswordResetClaim;
    }

    //#endregion
    //#region --- Create the handlers

    private _setAuthenticatePasswordClaimHandler(service: AuthenticationService<P>, ex: ExceptionService) {
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

    private _setAuthenticateAccessTokenClaimHandler(service: AuthenticationService<P>, ex: ExceptionService) {
        this._authenticateAccessTokenClaim = async (req, _, next) => {
            // authenticate
            const claim = createAccessTokenAuthClaim(GetAuthorizationHeader(req));
            req.securityContext = await service.authenticateAccessTokenClaim(claim);
            // advance
            if (!throwIfNotAuthenticated(req, ex)) {
                next();
            }
        };
    }

    private _setAuthenticatePasswordResetClaimHandler(service: AuthenticationService<P>, ex: ExceptionService) {
        this._authenticatePasswordResetClaim = async (req, _, next) => {
            // authenticate
            const claim = createPasswordResetAuthClaim(GetAuthorizationHeader(req));
            req.securityContext = await service.authenticatePasswordResetClaim(claim);
            // advance
            if (!throwIfNotAuthenticated(req, ex)) {
                next();
            }
        };
    }

    private _setAuthenticateTokenRefreshClaimHandler(service: AuthenticationService<P>, ex: ExceptionService) {
        this._authenticateTokenRefreshClaim = async (req, _, next) => {
            // authenticate
            const claim = createRefreshAccessTokenAuthClaim(GetAuthorizationHeader(req));
            req.securityContext = await service.authenticateTokenRefreshClaim(claim);
            // advance
            if (!throwIfNotAuthenticated(req, ex)) {
                next();
            }
        };
    }

    private _setAuthenticateVerifyClaimHandler(service: AuthenticationService<P>, ex: ExceptionService) {
        this._authenticateVerifyClaim = async (req, _, next) => {
            // authenticate
            const claim = createVerifyUserAuthClaim(GetAuthorizationHeader(req));
            req.securityContext = await service.authenticateVerifyClaim(claim);
            // advance
            if (!throwIfNotAuthenticated(req, ex)) {
                next();
            }
        };
    }

    //#endregion
}

function throwIfNotAuthenticated(req: ExpressLikeRequest, ex: ExceptionService): boolean {
    return !(req.securityContext.isAuthenticated || ex.throwUnauthenticated());
}
