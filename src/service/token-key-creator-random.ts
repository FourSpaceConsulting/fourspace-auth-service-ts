import { TokenKeyCreator } from "./token-key-creator";
import { AuthUser } from "../domain/auth-user";
import { RandomStringGenerator } from "./random-string-generator";

/**
 * Implementation that generates a random key
 */
export class TokenKeyCreatorRandom implements TokenKeyCreator {
    private readonly _randomStringGenerator: RandomStringGenerator;
    private readonly _keyLength: number;

    constructor(randomStringGenerator: RandomStringGenerator, keyLength: number) {
        this._randomStringGenerator = randomStringGenerator;
        this._keyLength = keyLength;
    }

    public createKey(user: AuthUser): Promise<string> {
        return this._randomStringGenerator.generateRandom(this._keyLength);
    }

}