import { SecureHashImpl } from './../src/service/secure-hash-impl';
import { TokenCreatorImpl } from './../src/service/token-creator-impl';
import { TokenAuthenticatorImpl } from './../src/service/token-authenticator-impl';
import { TokenKeyCreatorRandom } from './../src/service/token-key-creator-random';
import { RandomStringGeneratorImpl } from './../src/service/random-string-generator-impl';
import { TokenConverterImpl } from './../src/service/token-converter-impl';
import { DateProvider } from '../src/service/date-provider';
import { TokenDao } from '../src/dao/token-dao';
import { AuthToken, AuthTokenSecure } from '../src/domain/auth-token';
import moment from 'moment';

describe('Test Token Creation', () => {

    // Mock the token dao and date provider
    const TokenDaoMocker = jest.fn<TokenDao, [AuthTokenSecure]>((testToken) => ({
        getToken: jest.fn((key) => Promise.resolve(testToken.key === key ? testToken : null)),
        saveToken: jest.fn(),
    }));
    const DateProviderMocker = jest.fn<DateProvider, [Date]>((date) => ({
        getDateTime: jest.fn(() => date),
        saveToken: jest.fn(),
    }));

    // get a valid test token
    function getTestToken(): AuthToken {
        const testUser = { username: 'testUser@test.com' };
        const testDate: Date = moment(Date.UTC(2020, 1, 1)).toDate();
        return {
            key: 'IOhOX_7thgqJSbL8IzACweUcIP2D--',
            plainToken: 'RWyzKLK2aQqTVnSOD_NdsY-bbY6b656oqkImx2H62Bq1M7r_ea',
            hashToken: '$argon2id$v=19$m=65536,t=2,p=1$lu1rT+rmvqkp0BhPRH2r9A$kHkGkE3pnZT7sAy3Y7V263hWGvqvcNaAi37rnzHfGdM',
            created: testDate,
            user: testUser
        };
    }

    test('Test Token Creator Implementation', async () => {
        // arrange
        const testUser = { username: 'testUser@test.com' };
        const testDate = moment(Date.UTC(2020, 1, 1)).toDate();
        const dateProvider = new DateProviderMocker(testDate);
        const tokenLength = 50;
        const keyLength = 30;
        // act
        const randomStringGenerator = new RandomStringGeneratorImpl();
        const keyCreator = new TokenKeyCreatorRandom(randomStringGenerator, keyLength);
        const creator = new TokenCreatorImpl(keyCreator, new SecureHashImpl(), randomStringGenerator, dateProvider, tokenLength);
        const token = await creator.createAuthenticationToken(testUser);
        // assert
        expect(token).toBeTruthy();
        expect(token.key.length).toEqual(keyLength);
        expect(token.plainToken.length).toEqual(tokenLength);
        expect(token.created).toEqual(testDate);
    });

    test('Test Token Authenticator Success', async () => {
        // arrange
        const authToken = getTestToken();
        const encoder = new TokenConverterImpl(authToken.key.length);
        const testToken = encoder.encode(authToken.key, authToken.plainToken);
        // act
        const mockTokenDao = new TokenDaoMocker(authToken);
        const secureHash = new SecureHashImpl();
        const authenticator = new TokenAuthenticatorImpl(encoder, mockTokenDao, secureHash);
        const context = await authenticator.authenticateToken(testToken);
        // assert
        expect(mockTokenDao.getToken).toHaveBeenCalledTimes(1);
        expect(context.isAuthenticated).toBeTruthy();
        expect(context.principal).toEqual(authToken.user);
    });

    test('Test Token Authenticator Fail with Incorrect Key', async () => {
        // arrange
        const encoder = new TokenConverterImpl(30);
        const authToken = getTestToken();
        const testToken = encoder.encode('AOhOX_7thgqJSbL8IzACweUcIP2D--', authToken.plainToken);
        // act
        const mockTokenDao = new TokenDaoMocker(authToken);
        const secureHash = new SecureHashImpl();
        const authenticator = new TokenAuthenticatorImpl(encoder, mockTokenDao, secureHash);
        const context = await authenticator.authenticateToken(testToken);
        // assert
        expect(mockTokenDao.getToken).toHaveBeenCalledTimes(1);
        expect(context.isAuthenticated).toBeFalsy();
        expect(context.principal).toBe(null);
    });

    test('Test Token Authenticator Fail with Incorrect Token', async () => {
        // arrange
        const encoder = new TokenConverterImpl(30);
        const authToken = getTestToken();
        const testToken = encoder.encode(authToken.key, 'ZWyzKLK2aQqTVnSOD_NdsY-bbY6b656oqkImx2H62Bq1M7r_ea');
        // act
        const mockTokenDao = new TokenDaoMocker(authToken);
        const secureHash = new SecureHashImpl();
        const authenticator = new TokenAuthenticatorImpl(encoder, mockTokenDao, secureHash);
        const context = await authenticator.authenticateToken(testToken);
        // assert
        expect(mockTokenDao.getToken).toHaveBeenCalledTimes(1);
        expect(context.isAuthenticated).toBeFalsy();
        expect(context.principal).toBe(null);
    });

    test('Test Create and Authenticate Token', async () => {
        // arrange
        const testUser = { username: 'testUser@test.com' };
        const testDate = moment(Date.UTC(2020, 1, 1)).toDate();
        const dateProvider = new DateProviderMocker(testDate);
        const tokenLength = 50;
        const keyLength = 30;
        // act
        const encoder = new TokenConverterImpl(keyLength);
        const secureHash = new SecureHashImpl();
        const randomStringGenerator = new RandomStringGeneratorImpl();
        const keyCreator = new TokenKeyCreatorRandom(randomStringGenerator, keyLength);
        const creator = new TokenCreatorImpl(keyCreator, secureHash, randomStringGenerator, dateProvider, tokenLength);
        // - create new token, and set mock
        const authToken = await creator.createAuthenticationToken(testUser);
        const mockTokenDao = new TokenDaoMocker(authToken);
        // - authenticate encoded token 
        const encodedToken = encoder.encode(authToken.key, authToken.plainToken);
        const authenticator = new TokenAuthenticatorImpl(encoder, mockTokenDao, secureHash);
        const context = await authenticator.authenticateToken(encodedToken);
        // assert
        expect(mockTokenDao.getToken).toHaveBeenCalledTimes(1);
        expect(context.isAuthenticated).toBeTruthy();
        expect(context.principal).toEqual(authToken.user);
    });

});