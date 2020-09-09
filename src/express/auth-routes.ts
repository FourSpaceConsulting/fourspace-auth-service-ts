import { ApiMethod, SendResult, RouteConfiguration } from './express-util';
import { AuthController } from './auth-controller';
import { AuthHandlers } from './auth-handlers';
import { ValidationHandlers } from './validation-handlers';

type ApiRouteAdapter = (r: string) => string;

/**
 * Create the authentication routes for the express server
 * @param routeAdapter 
 * @param authHandlers 
 * @param validationHandlers 
 * @param c 
 */
export const authRoutes = <P>(
    routeAdapter: ApiRouteAdapter,
    authHandlers: AuthHandlers,
    validationHandlers: ValidationHandlers,
    c: AuthController
): RouteConfiguration[] => {
    return [
        {
            path: routeAdapter('/auth/register'),
            method: ApiMethod.POST,
            handler: [
                // no auth required for this action, but verify body values
                validationHandlers.validateInitialUsernameAndPassword,
                // perform action
                SendResult(r => c.registerUser(r)),
            ],
        },
        {
            path: routeAdapter('/auth/verify'),
            method: ApiMethod.POST,
            handler: [
                // authenticate the verification claim
                authHandlers.authenticateVerifyClaim,
                // perform action
                SendResult(r => c.verifyUser(r)),
            ],
        },
        {
            path: routeAdapter('/auth/login'),
            method: ApiMethod.POST,
            handler: [
                // authenticate the login claim
                authHandlers.authenticatePasswordClaim,
                // perform action
                SendResult(r => c.logIn(r)),
            ],
        },
        {
            path: routeAdapter('/auth/logout'),
            method: ApiMethod.POST,
            handler: [
                // authenticate the login claim
                authHandlers.authenticateTokenRefreshClaim,
                // perform action
                SendResult(r => c.logOut(r)),
            ],
        },
        {
            path: routeAdapter('/auth/refresh'),
            method: ApiMethod.POST,
            handler: [
                // authenticate the login claim
                authHandlers.authenticateTokenRefreshClaim,
                // perform action
                SendResult(r => c.refreshToken(r)),
            ],
        },
        {
            path: routeAdapter('/auth/request-reset'),
            method: ApiMethod.POST,
            handler: [
                // no authentication required for this action, but validate the username
                validationHandlers.validateUsername,
                // perform action
                SendResult(r => c.requestPasswordReset(r)),
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
                SendResult(r => c.performPasswordReset(r)),
            ],
        },
    ];
};
