import { AuthUser } from "./auth-user";
export interface AuthTokenSecure {
    readonly key: string;
    readonly hashToken: string;
    readonly created: Date;
    readonly user: AuthUser;
}

export interface AuthToken extends AuthTokenSecure {
    readonly plainToken: string;
}