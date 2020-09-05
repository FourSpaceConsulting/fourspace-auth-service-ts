import { MemoryDao } from './memory-dao';
import { TokenDao } from '../token-dao';
import { AuthTokenSecure } from '../../domain/auth-token';

/**
 * Demo token dao
 * Keeps tokens in memory using the 'key' property as ID.
 */
export class TokenDaoDemo<P> implements TokenDao<P> {
    private readonly _storage: MemoryDao<AuthTokenSecure<P>, string, object>;
    private readonly _key: string = ((prop: string & keyof AuthTokenSecure<P>) => prop)('key');

    constructor() {
        this._storage = new MemoryDao(this._key, () => false);
    }

    public getToken(key: string): Promise<AuthTokenSecure<P>> {
        return this._storage.getById(key);
    }

    public saveToken(token: AuthTokenSecure<P>): Promise<AuthTokenSecure<P>> {
        return this._storage.save(token);
    }
}
