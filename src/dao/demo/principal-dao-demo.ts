import { PrincipalDao } from '../principal-dao';
import { MemoryDao } from './memory-dao';
import { Principal } from '../../domain/principal';

/**
 * Demo Principal dao
 * Keeps principals in memory using the 'username' property as ID.
 */

export class PrincipalDaoDemo<P extends Principal> implements PrincipalDao<P> {
    private readonly _storage: MemoryDao<P, string, object>;
    private readonly _key: string = ((prop: string & keyof P) => prop)('username');

    constructor(items: ReadonlyArray<P>) {
        this._storage = new MemoryDao(this._key, () => false, 0, items);
    }

    public updatePrincipal(principal: P): Promise<P> {
        return this._storage.save(principal);
    }

    public savePrincipal(principal: P): Promise<P> {
        return this._storage.save(principal);
    }

    public getPrincipal(username: string): Promise<P> {
        return this._storage.getById(username);
    }
}
