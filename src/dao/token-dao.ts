import { AuthToken, AuthTokenSecure } from "../domain/auth-token";

export interface TokenDao {
    getToken(key: string): Promise<AuthTokenSecure>;
    saveToken(token: AuthTokenSecure): Promise<AuthTokenSecure>;
}