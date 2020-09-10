import { ActionSecurityContext, UserSecurityContext } from '../domain/security-context';
import { AuthTokenSecure } from '../domain/auth-token';
import { AuthExceptionService } from './exception-service';

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
export type ExpressLikeRequestHandler = (
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
    handler: ExpressLikeRequestHandler | ExpressLikeRequestHandler[];
};

//#endregion
