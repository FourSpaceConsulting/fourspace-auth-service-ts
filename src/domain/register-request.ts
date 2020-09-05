export interface RegisterRequest<P> {
    readonly newUser: P;
    readonly password: string;
}

export interface RegisterResponse {
    readonly isSuccess: boolean;
    readonly message?: string;
}
