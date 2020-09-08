/**
 * Types of authentication claim
 */
export enum AuthClaimType {
    PASSWORD,
    ACCESS_TOKEN,
    REFRESH_TOKEN,
    VERIFY_USER,
    PASSWORD_RESET,
}

/**
 * User access claim with username and password
 */
export interface PasswordAuthClaim {
    readonly claimType: AuthClaimType.PASSWORD;
    readonly user: string;
    readonly password: string;
}
/**
 * User access claim with an access token
 */
export interface AccessTokenAuthClaim {
    readonly claimType: AuthClaimType.ACCESS_TOKEN;
    readonly accessToken: string;
}
/**
 * Claim for refreshing the access token with a refresh token
 */
export interface RefreshAccessTokenAuthClaim {
    readonly claimType: AuthClaimType.REFRESH_TOKEN;
    readonly refreshToken: string;
}

/**
 * Claim for resetting the password, with a reset token
 */
export interface PasswordResetAuthClaim {
    readonly claimType: AuthClaimType.PASSWORD_RESET;
    readonly resetToken: string;
}

/**
 * Claim for verifying a user with a verify token
 */
export interface VerifyUserAuthClaim {
    readonly claimType: AuthClaimType.VERIFY_USER;
    readonly verifyToken: string;
}

export type AuthClaim =
    | PasswordAuthClaim
    | AccessTokenAuthClaim
    | RefreshAccessTokenAuthClaim
    | PasswordResetAuthClaim
    | VerifyUserAuthClaim;

/**
 * Convenience create method
 * @param user
 * @param password
 */
export const createPasswordAuthClaim = (user: string, password: string): PasswordAuthClaim => ({
    claimType: AuthClaimType.PASSWORD,
    user,
    password,
});

/**
 * Convenience create method
 * @param accessToken
 */
export const createAccessTokenAuthClaim = (accessToken: string): AccessTokenAuthClaim => ({
    claimType: AuthClaimType.ACCESS_TOKEN,
    accessToken,
});

/**
 * Convenience create method
 * @param refreshToken
 */
export const createRefreshAccessTokenAuthClaim = (refreshToken: string): RefreshAccessTokenAuthClaim => ({
    claimType: AuthClaimType.REFRESH_TOKEN,
    refreshToken,
});

/**
 * Convenience create method
 * @param user
 * @param resetToken
 */
export const createPasswordResetAuthClaim = (resetToken: string): PasswordResetAuthClaim => ({
    claimType: AuthClaimType.PASSWORD_RESET,
    resetToken,
});

/**
 * Convenience create method
 * @param user
 * @param verifyToken
 */
export const createVerifyUserAuthClaim = (verifyToken: string): VerifyUserAuthClaim => ({
    claimType: AuthClaimType.VERIFY_USER,
    verifyToken,
});
