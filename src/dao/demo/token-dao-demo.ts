import { MemoryDao } from './memory-dao';
import {
    TokenDao,
    SearchCriteria,
    TokenCriteriaSearchType,
    TokenSearchCriteriaSingleToken,
    TokenSearchCriteriaByTypeAndUser,
    TokenSearchCriteriaByUser,
} from '../token-dao';
import { AuthTokenSecure } from '../../domain/auth-token';
import { Principal } from '../../domain/principal';

/**
 * Demo token dao
 * Keeps tokens in memory using the 'key' property as ID.
 */
export class TokenDaoDemo<P extends Principal> implements TokenDao<P> {
    private readonly _storage: MemoryDao<AuthTokenSecure<P>, string, string>;
    private readonly _key: string = ((prop: string & keyof AuthTokenSecure<P>) => prop)('key');

    constructor() {
        this._storage = new MemoryDao(this._key, () => false);
    }

    public getAll(): Promise<ReadonlyArray<AuthTokenSecure<P>>> {
        return this._storage.get();
    }

    public getToken(key: string): Promise<AuthTokenSecure<P>> {
        return this._storage.getById(key);
    }

    public saveToken(token: AuthTokenSecure<P>): Promise<AuthTokenSecure<P>> {
        return this._storage.save(token);
    }

    public updateToken(token: AuthTokenSecure<P>): Promise<AuthTokenSecure<P>> {
        return this._storage.save(token);
    }

    public deleteTokens(sc: SearchCriteria<P>): Promise<void> {
        switch (sc.searchType) {
            case TokenCriteriaSearchType.Token:
                return this._deleteToken(sc);
            case TokenCriteriaSearchType.UserTokenType:
                return this._deleteTokenTypes(sc);
            case TokenCriteriaSearchType.User:
                return this._deleteUserTokens(sc);
        }
    }

    private async _deleteToken(sc: TokenSearchCriteriaSingleToken<P>): Promise<void> {
        return this._cascadeDelete(sc.token);
    }

    private async _deleteTokenTypes(sc: TokenSearchCriteriaByTypeAndUser): Promise<void> {
        const allItems = await this._storage.get();
        allItems
            .filter(t => t.tokenType === sc.tokenType && t.principal.username === sc.username)
            .forEach(j => this._cascadeDelete(j));
    }

    private async _deleteUserTokens(sc: TokenSearchCriteriaByUser): Promise<void> {
        const allItems = await this._storage.get();
        allItems.filter(t => t.principal.username === sc.username).forEach(j => this._cascadeDelete(j));
    }

    private async _cascadeDelete(t: AuthTokenSecure<P>) {
        const thisKey = t.key;
        // delete children
        const allItems = await this._storage.get();
        allItems.filter(i => i.associatedKey === thisKey).forEach(j => this._cascadeDelete(j));
        // delete this
        return this._storage.deleteItem(t);
    }
}
