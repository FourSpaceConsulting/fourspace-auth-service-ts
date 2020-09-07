export interface Principal {
    readonly username: string;
    encryptedPassword: string;
    isVerified: boolean;
}
