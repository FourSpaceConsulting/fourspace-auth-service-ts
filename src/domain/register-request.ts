export interface RegisterRequest<P> {
    readonly newPrincipal: P;
    readonly password: string;
}

export interface RegisterResponse {
    readonly isSuccess: boolean;
    readonly message?: string;
    readonly encodedToken: string;
}
