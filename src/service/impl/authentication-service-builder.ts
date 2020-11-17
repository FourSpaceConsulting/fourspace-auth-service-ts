import { PrincipalDao } from '../../dao/principal-dao';
import { AuthenticationService } from '../authentication-service';
import { TokenDao } from '../../dao/token-dao';
import { AuthenticationServiceImpl } from './authentication-service-impl';
import { UserAuthenticator } from '../user-authenticator';
import { UserAuthenticatorImpl } from './user-authenticator-impl';
import { SecureHash } from '../secure-hash';
import { SecureHashImpl } from './secure-hash-impl';
import { Principal } from '../../domain/principal';
import { TokenAuthenticator } from '../token-authenticator';
import { TokenAuthenticatorImpl } from './token-authenticator-impl';
import { TokenEncoder } from '../token-encoder';
import { TokenEncoderStringSeparated } from './token-encoder-string-separated';
import { TokenCreator } from '../token-creator';
import { TokenCreatorImpl, ExpiryConfig } from './token-creator-impl';
import { TokenKeyCreator } from '../token-key-creator';
import { TokenKeyCreatorRandom } from './token-key-creator-random';
import { RandomStringGenerator } from '../random-string-generator';
import { RandomStringGeneratorImpl } from './random-string-generator-impl';
import { DateProvider } from '../date-provider';
import { DateProviderSystem } from './date-provider-system';
import { PrincipalDaoDemo } from '../../dao/demo/principal-dao-demo';
import { TokenDaoDemo } from '../../dao/demo/token-dao-demo';
import { ActionMessageService } from '../../actions/action-message-service';
import { ActionMessageServiceDemo } from '../../actions/demo/action-message-service-demo';
import { ExpiryChecker } from '../expiry-checker';
import { ExpiryCheckerImpl } from './expiry-checker-impl';

export class AuthenticationServiceBuilder<P extends Principal> {
    private _principalDao: PrincipalDao<P>;
    private _tokenDao: TokenDao<P>;
    private _secureHash: SecureHash;
    private _actionMessageService: ActionMessageService<P>;
    private _userAuthenticator: UserAuthenticator<P>;
    private _tokenAuthenticator: TokenAuthenticator<P>;
    private _tokenEncoder: TokenEncoder;
    private _tokenCreator: TokenCreator<P>;
    private _tokenKeyCreator: TokenKeyCreator<P>;
    private _randomStringGenerator: RandomStringGenerator;
    private _expiryChecker: ExpiryChecker;
    private _dateProvider: DateProvider;
    private _tokenLength: number = 30;
    private _keyLength: number = 8;
    private _expiryConfig: ExpiryConfig = {
        verifyExpiry: 60,
        passwordResetExpiry: 10,
        accessExpiry: 30,
        refreshExpiry: 180,
    };

    public buildAuthenticationService(): AuthenticationService<P> {
        const userAuthenticator = this.getUserAuthenticator();
        const tokenAuthenticator = this.getTokenAuthenticator();
        const tokenCreator = this.getTokenCreator();
        return new AuthenticationServiceImpl(
            userAuthenticator,
            tokenAuthenticator,
            tokenCreator,
            this.getTokenEncoder(),
            this.getTokenDao(),
            this.getPrincipalDao(),
            this.getSecureHash(),
            this.getActionMessageService()
        );
    }

    /**
     * Getter principalDao
     * @return {PrincipalDao<P>}
     */
    private getPrincipalDao(): PrincipalDao<P> {
        if (this._principalDao == null) {
            this._principalDao = new PrincipalDaoDemo([]);
        }
        return this._principalDao;
    }

    /**
     * Setter principalDao
     * @param {PrincipalDao<P>} value
     */
    public setPrincipalDao(value: PrincipalDao<P>): AuthenticationServiceBuilder<P> {
        this._principalDao = value;
        return this;
    }

    /**
     * Getter tokenDao
     * @return {TokenDao<P>}
     */
    private getTokenDao(): TokenDao<P> {
        if (this._tokenDao == null) {
            this._tokenDao = new TokenDaoDemo();
        }
        return this._tokenDao;
    }

    /**
     * Setter tokenDao
     * @param {TokenDao<P>} value
     */
    public setTokenDao(value: TokenDao<P>): AuthenticationServiceBuilder<P> {
        this._tokenDao = value;
        return this;
    }

    /**
     * Getter actionMessageService
     * @return {ActionMessageService<P>}
     */
    private getActionMessageService(): ActionMessageService<P> {
        if (this._actionMessageService == null) {
            this._actionMessageService = new ActionMessageServiceDemo();
        }
        return this._actionMessageService;
    }

    /**
     * Setter actionMessageService
     * @param {ActionMessageService<P>} value
     */
    public setActionMessageService(value: ActionMessageService<P>) {
        this._actionMessageService = value;
        return this;
    }

    /**
     * Get secure hash or default version
     * @return {SecureHash}
     */
    private getSecureHash(): SecureHash {
        if (this._secureHash == null) {
            this._secureHash = new SecureHashImpl();
        }
        return this._secureHash;
    }

    /**
     * Setter secureHash
     * @param {SecureHash} value
     */
    public setSecureHash(value: SecureHash) {
        this._secureHash = value;
        return this;
    }

    /**
     * Getter userAuthenticator
     * @return {UserAuthenticator<P>}
     */
    private getUserAuthenticator(): UserAuthenticator<P> {
        if (this._userAuthenticator == null) {
            this._userAuthenticator = new UserAuthenticatorImpl<P>(this.getPrincipalDao(), this.getSecureHash());
        }
        return this._userAuthenticator;
    }

    /**
     * Setter userAuthenticator
     * @param {UserAuthenticator<P>} value
     */
    public setUserAuthenticator(value: UserAuthenticator<P>) {
        this._userAuthenticator = value;
        return this;
    }

    /**
     * Getter tokenAuthenticator
     * @return {TokenAuthenticator<P>}
     */
    private getTokenAuthenticator(): TokenAuthenticator<P> {
        if (this._tokenAuthenticator == null) {
            this._tokenAuthenticator = new TokenAuthenticatorImpl<P>(
                this.getTokenEncoder(),
                this.getTokenDao(),
                this.getSecureHash(),
                this.getExpiryChecker()
            );
        }
        return this._tokenAuthenticator;
    }

    /**
     * Setter tokenAuthenticator
     * @param {TokenAuthenticator<P>} value
     */
    public setTokenAuthenticator(value: TokenAuthenticator<P>) {
        this._tokenAuthenticator = value;
        return this;
    }

    /**
     * Getter tokenEncoder
     * @return {TokenEncoder}
     */
    private getTokenEncoder(): TokenEncoder {
        if (this._tokenEncoder == null) {
            this._tokenEncoder = new TokenEncoderStringSeparated('.');
        }
        return this._tokenEncoder;
    }

    /**
     * Setter tokenEncoder
     * @param {TokenEncoder} value
     */
    public setTokenEncoder(value: TokenEncoder) {
        this._tokenEncoder = value;
        return this;
    }

    /**
     * Getter tokenCreator
     * @return {TokenCreator<P>}
     */
    private getTokenCreator(): TokenCreator<P> {
        if (this._tokenCreator == null) {
            this._tokenCreator = new TokenCreatorImpl<P>(
                this.getTokenKeyCreator(),
                this.getSecureHash(),
                this.getRandomStringGenerator(),
                this.getDateProvider(),
                this.getTokenLength(),
                this.getExpiryConfig()
            );
        }
        return this._tokenCreator;
    }

    /**
     * Setter tokenCreator
     * @param {TokenCreator<P>} value
     */
    public setTokenCreator(value: TokenCreator<P>) {
        this._tokenCreator = value;
        return this;
    }

    /**
     * Getter tokenKeyCreator
     * @return {TokenKeyCreator<P>}
     */
    private getTokenKeyCreator(): TokenKeyCreator<P> {
        if (this._tokenKeyCreator == null) {
            this._tokenKeyCreator = new TokenKeyCreatorRandom<P>(this.getRandomStringGenerator(), this.getKeyLength());
        }
        return this._tokenKeyCreator;
    }

    /**
     * Setter tokenKeyCreator
     * @param {TokenKeyCreator<P>} value
     */
    public setTokenKeyCreator(value: TokenKeyCreator<P>) {
        this._tokenKeyCreator = value;
        return this;
    }

    /**
     * Getter keyLength
     * @return {number}
     */
    private getKeyLength(): number {
        return this._keyLength;
    }

    /**
     * Setter keyLength
     * @param {number} value
     */
    public setKeyLength(value: number) {
        this._keyLength = value;
        return this;
    }

    /**
     * Getter randomStringGenerator
     * @return {RandomStringGenerator}
     */
    private getRandomStringGenerator(): RandomStringGenerator {
        if (this._randomStringGenerator == null) {
            this._randomStringGenerator = new RandomStringGeneratorImpl();
        }
        return this._randomStringGenerator;
    }

    /**
     * Setter randomStringGenerator
     * @param {RandomStringGenerator} value
     */
    public setRandomStringGenerator(value: RandomStringGenerator) {
        this._randomStringGenerator = value;
        return this;
    }

    /**
     * Getter dateProvider
     * @return {DateProvider}
     */
    private getDateProvider(): DateProvider {
        if (this._dateProvider == null) {
            this._dateProvider = new DateProviderSystem();
        }
        return this._dateProvider;
    }

    /**
     * Setter dateProvider
     * @param {DateProvider} value
     */
    public setDateProvider(value: DateProvider) {
        this._dateProvider = value;
        return this;
    }

    /**
     * Getter expiryChecker
     * @return {ExpiryChecker}
     */
    public getExpiryChecker(): ExpiryChecker {
        if (this._expiryChecker == null) {
            this._expiryChecker = new ExpiryCheckerImpl(this.getDateProvider());
        }
        return this._expiryChecker;
    }

    /**
     * Setter expiryChecker
     * @param {ExpiryChecker} value
     */
    public setExpiryChecker(value: ExpiryChecker) {
        this._expiryChecker = value;
        return this;
    }

    /**
     * Getter tokenLength
     * @return {number }
     */
    private getTokenLength(): number {
        return this._tokenLength;
    }

    /**
     * Setter tokenLength
     * @param {number } value
     */
    public setTokenLength(value: number) {
        this._tokenLength = value;
        return this;
    }

    /**
     * Getter expiryConfig
     * @return {ExpiryConfig }
     */
    private getExpiryConfig(): ExpiryConfig {
        return this._expiryConfig;
    }

    /**
     * Setter expiryConfig
     * @param {ExpiryConfig } value
     */
    public setExpiryConfig(value: ExpiryConfig) {
        this._expiryConfig = value;
        return this;
    }
}
