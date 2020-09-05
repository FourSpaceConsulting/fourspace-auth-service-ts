import { TokenKeyCreator } from './../token-key-creator';
import { RandomStringGenerator } from './../random-string-generator';
import { UserSecurityContext } from '../../domain/security-context';

/**
 * Implementation that generates a random key
 */
export class TokenKeyCreatorRandom<P> implements TokenKeyCreator<P> {
    private readonly _randomStringGenerator: RandomStringGenerator;
    private readonly _keyLength: number;

    constructor(randomStringGenerator: RandomStringGenerator, keyLength: number) {
        this._randomStringGenerator = randomStringGenerator;
        this._keyLength = keyLength;
    }

    public createKey(context: P): Promise<string> {
        return this._randomStringGenerator.generateRandom(this._keyLength);
    }
}
