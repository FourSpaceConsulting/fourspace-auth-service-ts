import { AuthUser } from "../domain/auth-user";

export interface TokenKeyCreator {
    createKey(user: AuthUser): Promise<string>;
}