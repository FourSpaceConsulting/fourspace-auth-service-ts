export enum AuthClaimType {
  PASSWORD,
  TOKEN
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
export type AuthClaim = AuthPasswordClaim | AuthTokenClaim;

export const createTokenClaim = (token: string): AuthTokenClaim => ({
  claimType: AuthClaimType.TOKEN,
  token
});
