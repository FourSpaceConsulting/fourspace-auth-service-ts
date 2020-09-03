import { TokenCreator } from "./token-creator";
import { AuthUser } from "../domain/auth-user";
import { SecureHash } from "./secure-hash";
import { RandomStringGenerator } from "./random-string-generator";
import { DateProvider } from "./date-provider";
import { AuthToken } from "../domain/auth-token";
import { TokenKeyCreator } from "./token-key-creator";

/**
 * Token creator implementation
 */
export class TokenCreatorImpl implements TokenCreator {
    private readonly _secureHash: SecureHash;
    private readonly _randomStringGenerator: RandomStringGenerator;
    private readonly _tokenKeyCreator: TokenKeyCreator;
    private readonly _dateProvider: DateProvider;
    private readonly _tokenInputLength: number;

    /**
     * Construct the token creator
     * 
     * @param secureHash 
     * @param randomStringGenerator 
     * @param dateProvider 
     * @param tokenInputLength 
     */
    constructor(_tokenKeyCreator: TokenKeyCreator, secureHash: SecureHash, randomStringGenerator: RandomStringGenerator, dateProvider: DateProvider, tokenInputLength: number) {
        this._tokenKeyCreator = _tokenKeyCreator;
        this._secureHash = secureHash;
        this._randomStringGenerator = randomStringGenerator;
        this._dateProvider = dateProvider;
        this._tokenInputLength = tokenInputLength;
    }

    public async createAuthenticationToken(user: AuthUser): Promise<AuthToken> {
        const key = await this._tokenKeyCreator.createKey(user);
        const plainToken = await this._randomStringGenerator.generateRandom(this._tokenInputLength);
        const hashToken = await this._secureHash.createHash(plainToken);
        const created = this._dateProvider.getDateTime();
        return { key, plainToken, hashToken, created, user };
    }
}

