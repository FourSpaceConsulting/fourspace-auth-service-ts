import { AuthToken } from "../domain/auth-token";
import { AuthUser } from "../domain/auth-user";

export interface AuthenticationTokenManager {
    createEncryptedPassword(username: string, password: string): string;

    createUserToken(user: AuthUser): AuthToken;

    getUser(username: string, password: string): AuthUser;

    // boolean updateUserPassword(String username, String oldPassword, String newPassword);

    // String resetUserPassword(String username);
}
