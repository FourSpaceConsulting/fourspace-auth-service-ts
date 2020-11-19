import { ApiMethod, RouteConfiguration } from './express-interface';
import * as Util from './request-util';
import { AuthController } from './auth-controller';
import { AuthHandlers } from './auth-handlers';
import { AuthValidationHandlers } from './validation-handlers';

type ApiRouteAdapter = (r: string) => string;
/**
 * Create the authentication routes for the express server
 * @param routeAdapter
 * @param authHandlers
 * @param validationHandlers
 * @param c controller
 */
export const createAuthenticationRoutes = <PDTO>(
    routeAdapter: ApiRouteAdapter,
    authHandlers: AuthHandlers,
    validationHandlers: AuthValidationHandlers,
    c: AuthController<PDTO>
): RouteConfiguration[] => {
    return [
        {
            path: routeAdapter('/auth/register'),
            method: ApiMethod.POST,
            handler: [
                // no auth required for this action, but verify body values
                validationHandlers.validateInitialUsernameAndPassword,
                // perform action
                Util.sendResult(r => c.registerUser(r)),
            ],
        },
        {
            path: routeAdapter('/auth/verify'),
            method: ApiMethod.POST,
            handler: [
                // authenticate the verification claim
                authHandlers.authenticateVerifyClaim,
                // perform action
                Util.sendResult(r => c.verifyUser(r)),
            ],
        },
        {
            path: routeAdapter('/auth/login'),
            method: ApiMethod.POST,
            handler: [
                // authenticate the login claim
                authHandlers.authenticatePasswordClaim,
                // perform action
                Util.sendResult(r => c.logIn(r)),
            ],
        },
        {
            path: routeAdapter('/auth/user'),
            method: ApiMethod.GET,
            handler: [
                // authenticate the login claim
                authHandlers.authenticateAccessTokenClaim,
                // perform action
                Util.sendResult(r => c.getAuthenticatedUser(r)),
            ],
        },
        {
            path: routeAdapter('/auth/logout'),
            method: ApiMethod.POST,
            handler: [
                // authenticate the login claim
                authHandlers.authenticateTokenRefreshClaim,
                // perform action
                Util.sendResult(r => c.logOut(r)),
            ],
        },
        {
            path: routeAdapter('/auth/refresh'),
            method: ApiMethod.POST,
            handler: [
                // authenticate the login claim
                authHandlers.authenticateTokenRefreshClaim,
                // perform action
                Util.sendResult(r => c.refreshToken(r)),
            ],
        },
        {
            path: routeAdapter('/auth/request-reset'),
            method: ApiMethod.POST,
            handler: [
                // no authentication required for this action, but validate the username
                validationHandlers.validateUsername,
                // perform action
                Util.sendResult(r => c.requestPasswordReset(r)),
            ],
        },
        {
            path: routeAdapter('/auth/perform-reset'),
            method: ApiMethod.POST,
            handler: [
                // authenticate the claim
                authHandlers.authenticatePasswordResetClaim,
                // validate the password
                validationHandlers.validatePassword,
                // perform action
                Util.sendResult(r => c.performPasswordReset(r)),
            ],
        },
    ];
};
