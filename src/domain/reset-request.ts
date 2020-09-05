export interface ResetRequest {
    readonly username: string;
    readonly origin: string;
}

export interface ResetRequestResponse<P> {
    readonly success: boolean;
    readonly origin: string;
    readonly encodedToken: string;
    readonly principal: P;
}
