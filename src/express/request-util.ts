import {
    ActionSecurityContext,
    SecurityContext,
    SecurityContextType,
    UserSecurityContext,
} from '../domain/security-context';
import { AuthTokenSecure } from '../domain/auth-token';
import { AuthExceptionService } from './exception-service';
import { ExpressLikeRequest, ExpressLikeRequestHandler } from './express-interface';

/**
 * Sends a 200 response with the result of the request functor
 * @param f
 */
export function sendResult<T>(f: (req: ExpressLikeRequest) => Promise<T> | T): ExpressLikeRequestHandler {
    return async (request, response) => {
        const result = await f(request);
        response.status(200).json(result);
    };
}

//#region  --- Parameter and Body value helpers

type RequestValueGetter = (r: ExpressLikeRequest) => string;
export function createParameterGetter(p: string): RequestValueGetter {
    return r => r.params[p];
}
export function createBodyGetter(p: string): RequestValueGetter {
    return r => r.body[p];
}
export function getAuthorizationHeader(r: ExpressLikeRequest): string {
    return r.headers.authorization;
}

//#endregion
//#region  --- Security Context Helpers

export function getUserContextPrincipal<P>(r: ExpressLikeRequest, ex: AuthExceptionService): P {
    const context = r.securityContext as UserSecurityContext<P>;
    if (!context.isAuthenticated || context.contextType !== SecurityContextType.User || context.principal == null) {
        ex.throwInternalServer();
    }
    return context.principal;
}

export function getActionContextPrincipal<P>(r: ExpressLikeRequest, ex: AuthExceptionService): P {
    const context = r.securityContext as ActionSecurityContext<P>;
    if (
        !context.isAuthenticated ||
        context.contextType !== SecurityContextType.Action ||
        context.authToken == null ||
        context.authToken.principal == null
    ) {
        ex.throwInternalServer();
    }
    return context.authToken.principal;
}

export function getActionContextToken<P>(r: ExpressLikeRequest, ex: AuthExceptionService): AuthTokenSecure<P> {
    const context = r.securityContext as ActionSecurityContext<P>;
    if (
        !context.isAuthenticated ||
        context.contextType !== SecurityContextType.Action ||
        context.authToken == null ||
        context.authToken.principal == null
    ) {
        ex.throwInternalServer();
    }
    return context.authToken;
}

//#endregion
