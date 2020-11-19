export enum TokenType {
    VerifyUser,
    AccessToken,
    RefreshToken,
    PasswordResetToken,
    RememberMeToken,
}

export interface AuthTokenSecure<P> {
    readonly key: string;
    readonly encryptedToken: string;
    readonly tokenType: TokenType;
    readonly principal: P;
    readonly created: Date;
    readonly expiry: Date;
    readonly associatedKey?: string;
    readonly verifyUpdate?: string;
}

export interface AuthToken<P> extends AuthTokenSecure<P> {
    readonly plainToken: string;
}

export interface AccessTokenResponse {
    readonly accessToken: string;
    readonly refreshToken: string;
}
