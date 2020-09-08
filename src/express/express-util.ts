import { ActionSecurityContext, UserSecurityContext } from '../domain/security-context';
import { AuthTokenSecure } from '../domain/auth-token';
import { ExceptionService } from './exception-service';

//#region --- Express Like interfaces
//        --- These allow us to write express compatible code without actually having to import express

export interface ExpressLikeParamsDictionary {
    [key: string]: string;
}
export interface ExpressLikeNextFunction {
    // tslint:disable-next-line callable-types (In ts2.1 it thinks the type alias has no call signatures)
    (err?: any): void;
}
export interface ExpressLikeRequest {
    headers: ExpressLikeIncomingHttpHeaders;
    securityContext?: { isAuthenticated: boolean };
    params: ExpressLikeParamsDictionary;
    body: any;
}
export interface ExpressLikeResponse {
    status(code: number): this;
    json(j: any): any;
}
export interface ExpressLikeIncomingHttpHeaders {
    authorization?: string;
}

//#endregion
//#region --- Route Configuration

export enum ApiMethod {
    GET = 'get',
    POST = 'post',
}

/**
 * Handler for express routes
 */
export type ExpressLikeRouteHandler = (
    req: ExpressLikeRequest,
    res: ExpressLikeResponse,
    next: ExpressLikeNextFunction
) => Promise<void> | void;

/**
 * Configuration for an express route
 */
export type RouteConfiguration = {
    path: string;
    method: string;
    handler: ExpressLikeRouteHandler | ExpressLikeRouteHandler[];
};

/**
 * Sends a 200 response with the result of the request functor
 * @param f
 */
export function SendResult<T>(f: (req: ExpressLikeRequest) => Promise<T> | T): ExpressLikeRouteHandler {
    return async (r: ExpressLikeRequest, res: ExpressLikeResponse) => {
        const result = await f(r);
        res.status(200).json(result);
    };
}

//#endregion
//#region  --- Parameter and Body value helpers

type RequestValueGetter = (r: ExpressLikeRequest) => string;
export function CreateParameterGetter(p: string): RequestValueGetter {
    return r => r.params[p];
}
export function CreateBodyGetter(p: string): RequestValueGetter {
    return r => r.body[p];
}
export function GetAuthorizationHeader(r: ExpressLikeRequest): string {
    return r.headers.authorization;
}

//#endregion
//#region  --- Security Context Helpers

export function GetUserContextPrincipal<P>(r: ExpressLikeRequest, ex: ExceptionService): P {
    const context = r.securityContext as UserSecurityContext<P>;
    if (!context.isAuthenticated || context.principal == null) {
        ex.throwInternalServer();
    }
    return context.principal;
}

export function GetActionContextPrincipal<P>(r: ExpressLikeRequest, ex: ExceptionService): P {
    const context = r.securityContext as ActionSecurityContext<P>;
    if (!context.isAuthenticated || context.authToken == null || context.authToken.principal == null) {
        ex.throwInternalServer();
    }
    return context.authToken.principal;
}

export function GetActionContextToken<P>(r: ExpressLikeRequest, ex: ExceptionService): AuthTokenSecure<P> {
    const context = r.securityContext as ActionSecurityContext<P>;
    if (!context.isAuthenticated || context.authToken == null || context.authToken.principal == null) {
        ex.throwInternalServer();
    }
    return context.authToken;
}

//#endregion
