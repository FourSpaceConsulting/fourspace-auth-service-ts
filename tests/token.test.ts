import { SecureHashImpl } from './../src/service/impl/secure-hash-impl';
import { TokenCreatorImpl } from './../src/service/impl/token-creator-impl';
import { TokenAuthenticatorImpl } from './../src/service/impl/token-authenticator-impl';
import { TokenKeyCreatorRandom } from './../src/service/impl/token-key-creator-random';
import { RandomStringGeneratorImpl } from '../src/service/impl/random-string-generator-impl';
import { TokenEncoderStringSeparated } from '../src/service/impl/token-encoder-string-separated';
import { DateProvider } from '../src/service/date-provider';
import { TokenDao } from '../src/dao/token-dao';
import { AuthToken, AuthTokenSecure } from '../src/domain/auth-token';
import { Principal } from '../src/domain/principal';
import { UserSecurityContext } from '../src/domain/security-context';
import { createTokenClaim } from '../src/domain/auth-claim';
import moment from 'moment';
import { getTokenInfo } from '../src/service/util';

describe('Test Token Creation', () => {

    // Mock the token dao and date provider
    const TokenDaoMocker = jest.fn<TokenDao<Principal>, [AuthTokenSecure<Principal>]>((testToken) => ({
        getToken: jest.fn((key) => Promise.resolve(testToken.key === key ? testToken : null)),
        saveToken: jest.fn(),
    }));
    const DateProviderMocker = jest.fn<DateProvider, [Date]>((date) => ({
        getDateTime: jest.fn(() => date),
        saveToken: jest.fn(),
    }));

    // get a valid test token
    function getTestToken(): AuthToken<Principal> {
        const testUser = { username: 'testUser@test.com', passwordHash: '' };
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
        const testUser = { username: 'testUser@test.com', passwordHash: '' };
        const testContext: UserSecurityContext<Principal> = { isAuthenticated: true, authClaim: null, principal: testUser };
        const testDate = moment(Date.UTC(2020, 1, 1)).toDate();
        const dateProvider = new DateProviderMocker(testDate);
        const tokenLength = 50;
        const keyLength = 30;
        // act
        const randomStringGenerator = new RandomStringGeneratorImpl();
        const keyCreator = new TokenKeyCreatorRandom(randomStringGenerator, keyLength);
        const creator = new TokenCreatorImpl<Principal>(keyCreator, new SecureHashImpl(), randomStringGenerator, dateProvider, tokenLength);
        const token = await creator.createAuthenticationToken(testContext);
        // assert
        expect(token).toBeTruthy();
        expect(token.key.length).toEqual(keyLength);
        expect(token.plainToken.length).toEqual(tokenLength);
        expect(token.created).toEqual(testDate);
    });

    test('Test Token Authenticator Success', async () => {
        // arrange
        const authToken = getTestToken();
        const encoder = new TokenEncoderStringSeparated('.');
        const testClaim = createTokenClaim(encoder.encode(getTokenInfo(authToken)));
        // act
        const mockTokenDao = new TokenDaoMocker(authToken);
        const secureHash = new SecureHashImpl();
        const authenticator = new TokenAuthenticatorImpl(encoder, mockTokenDao, secureHash);
        const context = await authenticator.authenticateToken(testClaim);
        // assert
        expect(mockTokenDao.getToken).toHaveBeenCalledTimes(1);
        expect(context.isAuthenticated).toBeTruthy();
        expect(context.principal).toEqual(authToken.user);
    });

    test('Test Token Authenticator Fail with Incorrect Key', async () => {
        // arrange
        const encoder = new TokenEncoderStringSeparated('.');
        const authToken = getTestToken();
        const failAuthToken = { ...authToken, key: 'AOhOX_7thgqJSbL8IzACweUcIP2D--' };
        const testClaim = createTokenClaim(encoder.encode(getTokenInfo(failAuthToken)));
        // act
        const mockTokenDao = new TokenDaoMocker(authToken);
        const secureHash = new SecureHashImpl();
        const authenticator = new TokenAuthenticatorImpl(encoder, mockTokenDao, secureHash);
        const context = await authenticator.authenticateToken(testClaim);
        // assert
        expect(mockTokenDao.getToken).toHaveBeenCalledTimes(1);
        expect(context.isAuthenticated).toBeFalsy();
        expect(context.principal).toBe(null);
    });

    test('Test Token Authenticator Fail with Incorrect Token', async () => {
        // arrange
        const encoder = new TokenEncoderStringSeparated('.');
        const authToken = getTestToken();
        const failAuthToken = { ...authToken, plainToken: 'ZWyzKLK2aQqTVnSOD_NdsY-bbY6b656oqkImx2H62Bq1M7r_ea' };
        const testClaim = createTokenClaim(encoder.encode(getTokenInfo(failAuthToken)));
        // act
        const mockTokenDao = new TokenDaoMocker(authToken);
        const secureHash = new SecureHashImpl();
        const authenticator = new TokenAuthenticatorImpl(encoder, mockTokenDao, secureHash);
        const context = await authenticator.authenticateToken(testClaim);
        // assert
        expect(mockTokenDao.getToken).toHaveBeenCalledTimes(1);
        expect(context.isAuthenticated).toBeFalsy();
        expect(context.principal).toBe(null);
    });

    test('Test Create and Authenticate Token', async () => {
        // arrange
        const testUser = { username: 'testUser@test.com', passwordHash: '' };
        const testContext: UserSecurityContext<Principal> = { isAuthenticated: true, authClaim: null, principal: testUser };
        const testDate = moment(Date.UTC(2020, 1, 1)).toDate();
        const dateProvider = new DateProviderMocker(testDate);
        const tokenLength = 50;
        const keyLength = 30;
        // act
        const encoder = new TokenEncoderStringSeparated('.');
        const secureHash = new SecureHashImpl();
        const randomStringGenerator = new RandomStringGeneratorImpl();
        const keyCreator = new TokenKeyCreatorRandom(randomStringGenerator, keyLength);
        const creator = new TokenCreatorImpl<Principal>(keyCreator, secureHash, randomStringGenerator, dateProvider, tokenLength);
        // - create new token, and set mock
        const authToken = await creator.createAuthenticationToken(testContext);
        const mockTokenDao = new TokenDaoMocker(authToken);
        // - authenticate encoded token 
        const tokenClaim = createTokenClaim(encoder.encode(getTokenInfo(authToken)));
        const authenticator = new TokenAuthenticatorImpl(encoder, mockTokenDao, secureHash);
        const context = await authenticator.authenticateToken(tokenClaim);
        // assert
        expect(mockTokenDao.getToken).toHaveBeenCalledTimes(1);
        expect(context.isAuthenticated).toBeTruthy();
        expect(context.principal).toEqual(authToken.user);
    });

});