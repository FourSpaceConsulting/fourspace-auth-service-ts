import { Principal } from '../domain/principal';
import { UserSecurityContext } from '../domain/security-context';

export interface TokenKeyCreator<P> {
    createKey(user: P): Promise<string>;
}
