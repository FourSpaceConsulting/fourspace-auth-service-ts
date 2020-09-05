import SecurePassword from 'secure-password';
import { SecureHash } from '../secure-hash';

export class SecureHashImpl implements SecureHash {
    private readonly securePassword: SecurePassword;

    public constructor() {
        this.securePassword = new SecurePassword();
    }

    public async createHash(value: string): Promise<string> {
        return (await this.securePassword.hash(Buffer.from(value))).toString().replace(/\0/g, '');
    }

    public async verifyHash(value: string, hash: string): Promise<boolean> {
        const hashBuffer = Buffer.alloc(SecurePassword.HASH_BYTES);
        hashBuffer.write(hash);
        const result = await this.securePassword.verify(Buffer.from(value), hashBuffer);
        return result === SecurePassword.VALID || result === SecurePassword.VALID_NEEDS_REHASH;
    }
}
