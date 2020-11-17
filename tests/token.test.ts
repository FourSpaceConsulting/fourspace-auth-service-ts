import { SecureHashImpl } from './../src/service/impl/secure-hash-impl';
import { ExpiryCheckerImpl } from './../src/service/impl/expiry-checker-impl';
import { TokenCreatorImpl } from './../src/service/impl/token-creator-impl';
import { TokenAuthenticatorImpl } from './../src/service/impl/token-authenticator-impl';
import { TokenKeyCreatorRandom } from './../src/service/impl/token-key-creator-random';
import { RandomStringGeneratorImpl } from '../src/service/impl/random-string-generator-impl';
import { TokenEncoderStringSeparated } from '../src/service/impl/token-encoder-string-separated';
import { DateProvider } from '../src/service/date-provider';
import { TokenDao } from '../src/dao/token-dao';
import { AuthToken, AuthTokenSecure, TokenType } from '../src/domain/auth-token';
import { Principal } from '../src/domain/principal';
import { createAccessTokenAuthClaim } from '../src/domain/auth-claim';
import moment from 'moment';
import { getTokenInfo } from '../src/service/util';

describe('Test Token Creator, Authenticator and Encoder Implementations', () => {

    // Mock the token dao and date provider
    const TokenDaoMocker = jest.fn<TokenDao<Principal>, [AuthTokenSecure<Principal>]>((testToken) => ({
        getToken: jest.fn((key) => Promise.resolve(testToken.key === key ? testToken : null)),
        saveToken: jest.fn(),
        updateToken: jest.fn(),
        deleteTokens: jest.fn()
    }));
    const DateProviderMocker = jest.fn<DateProvider, [Date]>((date) => ({
        getDateTime: jest.fn(() => date),
        saveToken: jest.fn(),
    }));

    // get a valid test token
    function getTestToken(tokenType: TokenType): AuthToken<Principal> {
        const testUser = { username: 'testUser@test.com', encryptedPassword: '', isVerified: true };
        return {
            key: 'IOhOX_7thgqJSbL8IzACweUcIP2D--',
            plainToken: 'RWyzKLK2aQqTVnSOD_NdsY-bbY6b656oqkImx2H62Bq1M7r_ea',
            encryptedToken: '$argon2id$v=19$m=65536,t=2,p=1$lu1rT+rmvqkp0BhPRH2r9A$kHkGkE3pnZT7sAy3Y7V263hWGvqvcNaAi37rnzHfGdM',
            created: moment(Date.UTC(2020, 1, 1, 13)).toDate(),
            principal: testUser,
            expiry: moment(Date.UTC(2020, 1, 1, 14)).toDate(),
            tokenType,
        };
    }
    // create a test token creator
    const TestVerifyExpiry = 60;
    const TestPasswordResetExpiry = 10;
    const TestAccessExpiry = 30;
    const TestRefreshExpiry = 180;
    function buildTestTokenCreator(testDate: Date, keyLength: number, tokenLength: number) {
        const randomStringGenerator = new RandomStringGeneratorImpl();
        const dateProvider = new DateProviderMocker(testDate);
        const keyCreator = new TokenKeyCreatorRandom(randomStringGenerator, keyLength);
        const creator = new TokenCreatorImpl<Principal>(keyCreator, new SecureHashImpl(), randomStringGenerator, dateProvider, tokenLength, {
            verifyExpiry: TestVerifyExpiry,
            passwordResetExpiry: TestPasswordResetExpiry,
            accessExpiry: TestAccessExpiry,
            refreshExpiry: TestRefreshExpiry,
        });
        return creator;
    }
    function createExpiryChecker(testDate: Date) {
        return new ExpiryCheckerImpl(new DateProviderMocker(testDate));
    }

    test('Test token decode null safe', () => {
        const encoder = new TokenEncoderStringSeparated('.');
        // act
        const decoded = encoder.decode(undefined);
        // assert
        expect(decoded.tokenKey).toBeNull();
        expect(decoded.tokenValue).toBeNull();
        expect(decoded.expire).toBe(0);
    });


    test('Test token encoder', () => {
        const encoder = new TokenEncoderStringSeparated('.');
        const tokenInfo = {
            tokenKey: 'IOhOX_7thgqJSbL8IzACweUcIP2D--',
            tokenValue: 'RWyzKLK2aQqTVnSOD_NdsY-bbY6b656oqkImx2H62Bq1M7r_ea',
            expire: moment(Date.UTC(2100, 1, 1)).unix()
        };
        // act
        const encoded = encoder.encode(tokenInfo);
        const decoded = encoder.decode(encoded);
        // assert
        expect(encoded).toEqual('IOhOX_7thgqJSbL8IzACweUcIP2D--.RWyzKLK2aQqTVnSOD_NdsY-bbY6b656oqkImx2H62Bq1M7r_ea.Qe6V5rAAAAA=');
        expect(decoded.tokenKey).toEqual(tokenInfo.tokenKey);
        expect(decoded.tokenValue).toEqual(tokenInfo.tokenValue);
        expect(decoded.expire).toEqual(tokenInfo.expire);
    });

    test('Test create verify token', async () => {
        // arrange
        const testUser = { username: 'testUser@test.com', encryptedPassword: '', isVerified: true };
        const testDate = moment(Date.UTC(2020, 1, 1, 14, 20)).toDate();
        const tokenLength = 40;
        const keyLength = 20;
        const creator = buildTestTokenCreator(testDate, keyLength, tokenLength);
        // act
        const token = await creator.createVerifyToken(testUser);
        // assert
        expect(token).toBeTruthy();
        expect(token.tokenType).toEqual(TokenType.VerifyUser);
        expect(token.key.length).toEqual(keyLength);
        expect(token.plainToken.length).toEqual(tokenLength);
        expect(token.created).toEqual(testDate);
        expect(token.expiry).toEqual(moment(testDate).add(TestVerifyExpiry, 'minute').toDate());
    });


    test('Test create access token', async () => {
        // arrange
        const testUser = { username: 'testUser@test.com', encryptedPassword: '', isVerified: true };
        const testDate = moment(Date.UTC(2020, 1, 1, 14, 20)).toDate();
        const tokenLength = 50;
        const keyLength = 30;
        const creator = buildTestTokenCreator(testDate, keyLength, tokenLength);
        // act
        const token = await creator.createAccessToken(testUser);
        // assert
        expect(token).toBeTruthy();
        expect(token.tokenType).toEqual(TokenType.AccessToken);
        expect(token.key.length).toEqual(keyLength);
        expect(token.plainToken.length).toEqual(tokenLength);
        expect(token.created).toEqual(testDate);
        expect(token.expiry).toEqual(moment(testDate).add(TestAccessExpiry, 'minute').toDate());
    });

    test('Test create password reset token', async () => {
        // arrange
        const testUser = { username: 'testUser@test.com', encryptedPassword: '', isVerified: true };
        const testDate = moment(Date.UTC(2020, 1, 1, 14, 20)).toDate();
        const tokenLength = 40;
        const keyLength = 20;
        const creator = buildTestTokenCreator(testDate, keyLength, tokenLength);
        // act
        const token = await creator.createPasswordResetToken(testUser);
        // assert
        expect(token).toBeTruthy();
        expect(token.tokenType).toEqual(TokenType.PasswordResetToken);
        expect(token.key.length).toEqual(keyLength);
        expect(token.plainToken.length).toEqual(tokenLength);
        expect(token.created).toEqual(testDate);
        expect(token.expiry).toEqual(moment(testDate).add(TestPasswordResetExpiry, 'minute').toDate());
    });

    test('Test create refresh token', async () => {
        // arrange
        const testUser = { username: 'testUser@test.com', encryptedPassword: '', isVerified: true };
        const testDate = moment(Date.UTC(2020, 1, 1, 14, 20)).toDate();
        const tokenLength = 40;
        const keyLength = 20;
        const creator = buildTestTokenCreator(testDate, keyLength, tokenLength);
        // act
        const token = await creator.createRefreshToken(testUser);
        // assert
        expect(token).toBeTruthy();
        expect(token.tokenType).toEqual(TokenType.RefreshToken);
        expect(token.key.length).toEqual(keyLength);
        expect(token.plainToken.length).toEqual(tokenLength);
        expect(token.created).toEqual(testDate);
        expect(token.expiry).toEqual(moment(testDate).add(TestRefreshExpiry, 'minute').toDate());
    });


    test('Test Token Authenticator Success', async () => {
        // arrange
        const authToken = getTestToken(TokenType.AccessToken);
        const encoder = new TokenEncoderStringSeparated('.');
        const testClaim = createAccessTokenAuthClaim(encoder.encode(getTokenInfo(authToken)));
        const testDate = moment(Date.UTC(2020, 1, 1, 13, 20)).toDate();
        const expiryChecker = createExpiryChecker(testDate);
        // act
        const mockTokenDao = new TokenDaoMocker(authToken);
        const secureHash = new SecureHashImpl();
        const authenticator = new TokenAuthenticatorImpl(encoder, mockTokenDao, secureHash, expiryChecker);
        const context = await authenticator.authenticateAccessToken(testClaim);
        // assert
        expect(mockTokenDao.getToken).toHaveBeenCalledTimes(1);
        expect(context.isAuthenticated).toBeTruthy();
        expect(context.principal).toEqual(authToken.principal);
    });

    test('Test Token Authenticator Fail due to expiry', async () => {
        // arrange
        const authToken = getTestToken(TokenType.AccessToken);
        const encoder = new TokenEncoderStringSeparated('.');
        const testClaim = createAccessTokenAuthClaim(encoder.encode(getTokenInfo(authToken)));
        const testDate = moment(Date.UTC(2020, 1, 1, 14, 1)).toDate();
        const expiryChecker = createExpiryChecker(testDate);
        // act
        const mockTokenDao = new TokenDaoMocker(authToken);
        const secureHash = new SecureHashImpl();
        const authenticator = new TokenAuthenticatorImpl(encoder, mockTokenDao, secureHash, expiryChecker);
        const context = await authenticator.authenticateAccessToken(testClaim);
        // assert
        expect(mockTokenDao.getToken).toHaveBeenCalledTimes(1);
        expect(context.isAuthenticated).toBeFalsy();
        expect(context.principal).toBe(null);
    });

    test('Test Token Authenticator Fail with Incorrect Key', async () => {
        // arrange
        const encoder = new TokenEncoderStringSeparated('.');
        const authToken = getTestToken(TokenType.AccessToken);
        const failAuthToken = { ...authToken, key: 'AOhOX_7thgqJSbL8IzACweUcIP2D--' };
        const testClaim = createAccessTokenAuthClaim(encoder.encode(getTokenInfo(failAuthToken)));
        const testDate = moment(Date.UTC(2020, 1, 1, 14, 20)).toDate();
        const expiryChecker = createExpiryChecker(testDate);
        // act
        const mockTokenDao = new TokenDaoMocker(authToken);
        const secureHash = new SecureHashImpl();
        const authenticator = new TokenAuthenticatorImpl(encoder, mockTokenDao, secureHash, expiryChecker);
        const context = await authenticator.authenticateAccessToken(testClaim);
        // assert
        expect(mockTokenDao.getToken).toHaveBeenCalledTimes(1);
        expect(context.isAuthenticated).toBeFalsy();
        expect(context.principal).toBe(null);
    });

    test('Test Token Authenticator Fail with Incorrect Token', async () => {
        // arrange
        const encoder = new TokenEncoderStringSeparated('.');
        const authToken = getTestToken(TokenType.AccessToken);
        const failAuthToken = { ...authToken, plainToken: 'ZWyzKLK2aQqTVnSOD_NdsY-bbY6b656oqkImx2H62Bq1M7r_ea' };
        const testClaim = createAccessTokenAuthClaim(encoder.encode(getTokenInfo(failAuthToken)));
        const testDate = moment(Date.UTC(2020, 1, 1, 14, 20)).toDate();
        const expiryChecker = createExpiryChecker(testDate);
        // act
        const mockTokenDao = new TokenDaoMocker(authToken);
        const secureHash = new SecureHashImpl();
        const authenticator = new TokenAuthenticatorImpl(encoder, mockTokenDao, secureHash, expiryChecker);
        const context = await authenticator.authenticateAccessToken(testClaim);
        // assert
        expect(mockTokenDao.getToken).toHaveBeenCalledTimes(1);
        expect(context.isAuthenticated).toBeFalsy();
        expect(context.principal).toBe(null);
    });

    test('Test Token Authenticator Fail with Incorrect Type', async () => {
        // arrange
        const encoder = new TokenEncoderStringSeparated('.');
        const authToken = getTestToken(TokenType.RefreshToken);
        const testClaim = createAccessTokenAuthClaim(encoder.encode(getTokenInfo(authToken)));
        const testDate = moment(Date.UTC(2020, 1, 1, 14, 20)).toDate();
        const expiryChecker = createExpiryChecker(testDate);
        // act
        const mockTokenDao = new TokenDaoMocker(authToken);
        const secureHash = new SecureHashImpl();
        const authenticator = new TokenAuthenticatorImpl(encoder, mockTokenDao, secureHash, expiryChecker);
        const context = await authenticator.authenticateAccessToken(testClaim);
        // assert
        expect(mockTokenDao.getToken).toHaveBeenCalledTimes(1);
        expect(context.isAuthenticated).toBeFalsy();
        expect(context.principal).toBe(null);
    });



    test('Test Create and Authenticate Token', async () => {
        // arrange
        const testUser = { username: 'testUser@test.com', encryptedPassword: '', isVerified: true };
        const testDate = moment(Date.UTC(2020, 1, 1, 13)).toDate();
        const dateProvider = new DateProviderMocker(testDate);
        const expiryChecker = createExpiryChecker(testDate);
        const tokenLength = 50;
        const keyLength = 30;
        // act
        const encoder = new TokenEncoderStringSeparated('.');
        const secureHash = new SecureHashImpl();
        const randomStringGenerator = new RandomStringGeneratorImpl();
        const keyCreator = new TokenKeyCreatorRandom(randomStringGenerator, keyLength);
        const creator = new TokenCreatorImpl<Principal>(keyCreator, secureHash, randomStringGenerator, dateProvider, tokenLength, {
            verifyExpiry: 60,
            passwordResetExpiry: 10,
            accessExpiry: 30,
            refreshExpiry: 180,
        });
        // - create new token, and set mock
        const authToken = await creator.createAccessToken(testUser);
        const mockTokenDao = new TokenDaoMocker(authToken);
        // - authenticate encoded token 
        const tokenClaim = createAccessTokenAuthClaim(encoder.encode(getTokenInfo(authToken)));
        const authenticator = new TokenAuthenticatorImpl(encoder, mockTokenDao, secureHash, expiryChecker);
        const context = await authenticator.authenticateAccessToken(tokenClaim);
        // assert
        expect(mockTokenDao.getToken).toHaveBeenCalledTimes(1);
        expect(context.isAuthenticated).toBeTruthy();
        expect(context.principal).toEqual(authToken.principal);
    });

});