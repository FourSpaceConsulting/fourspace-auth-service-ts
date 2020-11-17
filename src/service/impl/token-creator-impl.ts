import { TokenCreator } from '../token-creator';
import { SecureHash } from './../secure-hash';
import { RandomStringGenerator } from './../random-string-generator';
import { DateProvider } from './../date-provider';
import { AuthToken, TokenType, AuthTokenSecure } from '../../domain/auth-token';
import { TokenKeyCreator } from './../token-key-creator';
import moment from 'moment';

/**
 * Token expiry configuration
 */
export interface ExpiryConfig {
    verifyExpiry: number;
    passwordResetExpiry: number;
    accessExpiry: number;
    refreshExpiry: number;
}

/**
 * Get the expiry minutes for a particular token type
 * @param expiryConfig
 * @param type
 */
export function getConfigExpiry(expiryConfig: ExpiryConfig, type: TokenType): number {
    switch (type) {
        case TokenType.AccessToken:
            return expiryConfig.accessExpiry;
        case TokenType.PasswordResetToken:
            return expiryConfig.passwordResetExpiry;
        case TokenType.RefreshToken:
            return expiryConfig.refreshExpiry;
        case TokenType.VerifyUser:
            return expiryConfig.verifyExpiry;
        default:
            return 0;
    }
}

/**
 * Token creator implementation
 */
export class TokenCreatorImpl<P> implements TokenCreator<P> {
    private readonly _expiry: ExpiryConfig;
    private readonly _secureHash: SecureHash;
    private readonly _randomStringGenerator: RandomStringGenerator;
    private readonly _tokenKeyCreator: TokenKeyCreator<P>;
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
    constructor(
        tokenKeyCreator: TokenKeyCreator<P>,
        secureHash: SecureHash,
        randomStringGenerator: RandomStringGenerator,
        dateProvider: DateProvider,
        tokenInputLength: number,
        expiry: ExpiryConfig
    ) {
        this._tokenKeyCreator = tokenKeyCreator;
        this._secureHash = secureHash;
        this._randomStringGenerator = randomStringGenerator;
        this._dateProvider = dateProvider;
        this._tokenInputLength = tokenInputLength;
        this._expiry = expiry;
    }

    public createVerifyToken(user: P): Promise<AuthToken<P>> {
        const created = this._dateProvider.getDateTime();
        const expiry = this._getExpiry(created, this._expiry.verifyExpiry);
        return this._createToken(user, TokenType.VerifyUser, created, expiry);
    }

    public createPasswordResetToken(user: P): Promise<AuthToken<P>> {
        const created = this._dateProvider.getDateTime();
        const expiry = this._getExpiry(created, this._expiry.passwordResetExpiry);
        return this._createToken(user, TokenType.PasswordResetToken, created, expiry);
    }

    public createAccessToken(user: P): Promise<AuthToken<P>> {
        const created = this._dateProvider.getDateTime();
        const expiry = this._getExpiry(created, this._expiry.accessExpiry);
        return this._createToken(user, TokenType.AccessToken, created, expiry);
    }

    public createRefreshToken(user: P): Promise<AuthToken<P>> {
        const created = this._dateProvider.getDateTime();
        const expiry = this._getExpiry(created, this._expiry.refreshExpiry);
        return this._createToken(user, TokenType.RefreshToken, created, expiry);
    }

    public async updateRefreshToken(currentToken: AuthTokenSecure<P>): Promise<AuthToken<P>> {
        const expiry = this._getExpiry(this._dateProvider.getDateTime(), this._expiry.refreshExpiry);
        const plainToken = await this._randomStringGenerator.generateRandom(this._tokenInputLength);
        const encryptedToken = await this._secureHash.createHash(plainToken);
        return {
            ...currentToken,
            expiry,
            plainToken,
            encryptedToken,
        };
    }

    private _getExpiry(from: Date, minutes: number): Date {
        return moment(from)
            .add(minutes, 'minute')
            .toDate();
    }

    private async _createToken(user: P, tokenType: TokenType, created: Date, expiry: Date): Promise<AuthToken<P>> {
        const key = await this._tokenKeyCreator.createKey(user);
        const plainToken = await this._randomStringGenerator.generateRandom(this._tokenInputLength);
        const encryptedToken = await this._secureHash.createHash(plainToken);
        return {
            tokenType,
            key,
            plainToken,
            encryptedToken,
            principal: user,
            created,
            expiry,
        };
    }
}
