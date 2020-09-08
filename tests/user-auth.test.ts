import { SecureHashImpl } from '../src/service/impl/secure-hash-impl';
import { UserAuthenticatorImpl } from '../src/service/impl/user-authenticator-impl';
import { PrincipalDao } from '../src/dao/principal-dao';
import { AuthToken, AuthTokenSecure, TokenType } from '../src/domain/auth-token';
import { Principal } from '../src/domain/principal';
import { createPasswordAuthClaim } from '../src/domain/auth-claim';
import moment from 'moment';

describe('Test User Authentication', () => {

    // Mock the token dao and date provider
    const PricipalDaoMocker = jest.fn<PrincipalDao<Principal>, [Principal]>((principal) => ({
        getPrincipal: jest.fn((key) => Promise.resolve(principal.username === key ? principal : null)),
        savePrincipal: jest.fn(),
        updatePrincipal: jest.fn()
    }));

    test('Test User Authenticator Success', async () => {
        // arrange
        const username = 'testUser@test.com';
        const password = 'testpassword';
        const encryptedPassword = '$argon2id$v=19$m=65536,t=2,p=1$63rP0KVWybD9jDS5vCqlLA$2v8XhYF9m/y0yPMIese5IS7FxDBwT1XwjHJ0xzg8thE';
        const testPrincipal = { username, encryptedPassword, isVerified: true };
        const testClaim = createPasswordAuthClaim(username, password);
        // act
        const mockPrincipalDao = new PricipalDaoMocker(testPrincipal);
        const secureHash = new SecureHashImpl();
        const authenticator = new UserAuthenticatorImpl(mockPrincipalDao, secureHash);
        const context = await authenticator.authenticateUser(testClaim);
        // assert
        expect(mockPrincipalDao.getPrincipal).toHaveBeenCalledTimes(1);
        expect(context.isAuthenticated).toBeTruthy();
        expect(context.principal).toEqual(testPrincipal);
    });

    // test('Test Token Authenticator Fail with Incorrect Key', async () => {
    //     // arrange
    //     const encoder = new TokenConverterImpl(30);
    //     const authToken = getTestToken();
    //     const testClaim = createTokenClaim(encoder.encode('AOhOX_7thgqJSbL8IzACweUcIP2D--', authToken.plainToken));
    //     // act
    //     const mockTokenDao = new TokenDaoMocker(authToken);
    //     const secureHash = new SecureHashImpl();
    //     const authenticator = new TokenAuthenticatorImpl(encoder, mockTokenDao, secureHash);
    //     const context = await authenticator.authenticateToken(testClaim);
    //     // assert
    //     expect(mockTokenDao.getToken).toHaveBeenCalledTimes(1);
    //     expect(context.isAuthenticated).toBeFalsy();
    //     expect(context.principal).toBe(null);
    // });

    // test('Test Token Authenticator Fail with Incorrect Token', async () => {
    //     // arrange
    //     const encoder = new TokenConverterImpl(30);
    //     const authToken = getTestToken();
    //     const testClaim = createTokenClaim(encoder.encode(authToken.key, 'ZWyzKLK2aQqTVnSOD_NdsY-bbY6b656oqkImx2H62Bq1M7r_ea'));
    //     // act
    //     const mockTokenDao = new TokenDaoMocker(authToken);
    //     const secureHash = new SecureHashImpl();
    //     const authenticator = new TokenAuthenticatorImpl(encoder, mockTokenDao, secureHash);
    //     const context = await authenticator.authenticateToken(testClaim);
    //     // assert
    //     expect(mockTokenDao.getToken).toHaveBeenCalledTimes(1);
    //     expect(context.isAuthenticated).toBeFalsy();
    //     expect(context.principal).toBe(null);
    // });

    // test('Test Create and Authenticate Token', async () => {
    //     // arrange
    //     const testUser = { username: 'testUser@test.com', encryptedPassword: '' };
    //     const testContext: UserSecurityContext<Principal> = { isAuthenticated: true, authClaim: null, principal: testUser };
    //     const testDate = moment(Date.UTC(2020, 1, 1)).toDate();
    //     const dateProvider = new DateProviderMocker(testDate);
    //     const tokenLength = 50;
    //     const keyLength = 30;
    //     // act
    //     const encoder = new TokenConverterImpl(keyLength);
    //     const secureHash = new SecureHashImpl();
    //     const randomStringGenerator = new RandomStringGeneratorImpl();
    //     const keyCreator = new TokenKeyCreatorRandom(randomStringGenerator, keyLength);
    //     const creator = new TokenCreatorImpl<Principal>(keyCreator, secureHash, randomStringGenerator, dateProvider, tokenLength);
    //     // - create new token, and set mock
    //     const authToken = await creator.createAuthenticationToken(testContext);
    //     const mockTokenDao = new TokenDaoMocker(authToken);
    //     // - authenticate encoded token 
    //     const tokenClaim = createTokenClaim(encoder.encode(authToken.key, authToken.plainToken));
    //     const authenticator = new TokenAuthenticatorImpl(encoder, mockTokenDao, secureHash);
    //     const context = await authenticator.authenticateToken(tokenClaim);
    //     // assert
    //     expect(mockTokenDao.getToken).toHaveBeenCalledTimes(1);
    //     expect(context.isAuthenticated).toBeTruthy();
    //     expect(context.principal).toEqual(authToken.user);
    // });

});