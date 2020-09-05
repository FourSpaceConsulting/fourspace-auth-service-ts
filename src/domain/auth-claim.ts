export enum AuthClaimType {
    PASSWORD,
    TOKEN,
    PASSWORD_RESET,
}
export interface AuthTokenClaim {
    readonly claimType: AuthClaimType.TOKEN;
    readonly token: string;
}
export interface AuthPasswordClaim {
    readonly claimType: AuthClaimType.PASSWORD;
    readonly user: string;
    readonly password: string;
}
export interface AuthPasswordResetClaim {
    readonly claimType: AuthClaimType.PASSWORD_RESET;
    readonly user: string;
    readonly resetToken: string;
}

export type AuthClaim = AuthPasswordClaim | AuthTokenClaim | AuthPasswordResetClaim;

export const createTokenClaim = (token: string): AuthTokenClaim => ({
    claimType: AuthClaimType.TOKEN,
    token,
});

export const createPasswordClaim = (user: string, password: string): AuthPasswordClaim => ({
    claimType: AuthClaimType.PASSWORD,
    user,
    password,
});

export const createPasswordResetClaim = (user: string, resetToken: string): AuthPasswordResetClaim => ({
    claimType: AuthClaimType.PASSWORD_RESET,
    user,
    resetToken,
});
