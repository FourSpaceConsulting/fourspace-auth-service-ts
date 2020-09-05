export enum TokenType {
    UserToken = 'UserToken',
    ResetToken = 'ResetToken',
}

export interface AuthTokenSecure<P> {
    readonly key: string;
    readonly hashToken: string;
    readonly tokenType: TokenType;
    readonly user: P;
    readonly created: Date;
    readonly expiry: Date;
}

export interface AuthToken<P> extends AuthTokenSecure<P> {
    readonly plainToken: string;
}
