import { AuthenticationServiceBuilder } from '../src/service/impl/authentication-service-builder';
import { PrincipalDao } from '../src/dao/principal-dao';
import { AuthToken, AuthTokenSecure, TokenType } from '../src/domain/auth-token';
import { Principal } from '../src/domain/principal';
import { createPasswordClaim, createTokenClaim, createPasswordResetClaim } from '../src/domain/auth-claim';
import { TokenDao } from '../src/dao/token-dao';
import moment from 'moment';
import { PrincipalDaoDemo } from '../src/dao/demo/principal-dao-demo';

describe('Test Service Builder', () => {

    // Mock the dao objects
    const PrincipalDaoMocker = jest.fn<PrincipalDao<Principal>, [Principal]>((principal) => ({
        getPrincipal: jest.fn((key) => Promise.resolve(principal.username === key ? principal : null)),
    }));
    const TokenDaoMocker = jest.fn<TokenDao<Principal>, [AuthTokenSecure<Principal>]>((testToken) => ({
        getToken: jest.fn((key) => Promise.resolve(testToken.key === key ? testToken : null)),
        saveToken: jest.fn(),
    }));

    // get a valid test token
    function getTestToken(): AuthToken<Principal> {
        const testUser = { username: 'testUser@test.com', passwordHash: '' };
        const testDate: Date = moment(Date.UTC(2020, 1, 1)).toDate();
        return {
            tokenType: TokenType.UserToken,
            key: 'IOhOX_7thgqJSbL8IzACweUcIP2D--',
            plainToken: 'RWyzKLK2aQqTVnSOD_NdsY-bbY6b656oqkImx2H62Bq1M7r_ea',
            hashToken: '$argon2id$v=19$m=65536,t=2,p=1$lu1rT+rmvqkp0BhPRH2r9A$kHkGkE3pnZT7sAy3Y7V263hWGvqvcNaAi37rnzHfGdM',
            created: testDate,
            expiry: testDate,
            user: testUser
        };
    }

    test('Test default builder mock dao password verify', async () => {
        // arrange
        const username = 'testUser@test.com';
        const password = 'testpassword';
        const passwordHash = '$argon2id$v=19$m=65536,t=2,p=1$63rP0KVWybD9jDS5vCqlLA$2v8XhYF9m/y0yPMIese5IS7FxDBwT1XwjHJ0xzg8thE';
        const testPrincipal = { username, passwordHash };
        const testToken = getTestToken();
        const testPasswordClaim = createPasswordClaim(username, password);
        // act
        const mockPrincipalDao = new PrincipalDaoMocker(testPrincipal);
        const mockTokenDao = new TokenDaoMocker(testToken);
        const manager = new AuthenticationServiceBuilder()
            .setPrincipalDao(mockPrincipalDao)
            .setTokenDao(mockTokenDao)
            .buildAuthenticationManager();
        const context = await manager.verifyPasswordClaim(testPasswordClaim);
        // assert
        expect(mockTokenDao.getToken).toHaveBeenCalledTimes(0);
        expect(mockPrincipalDao.getPrincipal).toHaveBeenCalledTimes(1);
        expect(context.isAuthenticated).toBeTruthy();
        expect(context.principal).toEqual(testPrincipal);
    });

    test('Test default builder password and token workflow', async () => {
        // arrange
        const username = 'testUser@test.com';
        const password = 'testpassword';
        const passwordHash = '$argon2id$v=19$m=65536,t=2,p=1$63rP0KVWybD9jDS5vCqlLA$2v8XhYF9m/y0yPMIese5IS7FxDBwT1XwjHJ0xzg8thE';
        const testPrincipal = { username, passwordHash };
        const testPasswordClaim = createPasswordClaim(username, password);
        // act
        const manager = new AuthenticationServiceBuilder()
            .setPrincipalDao(new PrincipalDaoDemo([testPrincipal]))
            .buildAuthenticationManager();
        const passwordContext = await manager.verifyPasswordClaim(testPasswordClaim);
        const newToken = await manager.createUserToken(passwordContext);
        const tokenContext = await manager.verifyTokenClaim(createTokenClaim(newToken));
        // assert
        expect(passwordContext.isAuthenticated).toBeTruthy();
        expect(passwordContext.principal).toEqual(testPrincipal);
        expect(tokenContext.isAuthenticated).toBeTruthy();
        expect(tokenContext.principal).toEqual(testPrincipal);
    });

    test('Test service reset password', () => {
        // arrange
        const username = 'testUser@test.com';
        const password = 'testpassword';
        const testPrincipal = { username, passwordHash: '' };
        // act
        const service = new AuthenticationServiceBuilder()
            .setPrincipalDao(new PrincipalDaoDemo([testPrincipal]))
            .buildAuthenticationManager();
        //const response = service.requestResetPassword({ username, origin: 'Test' });
        // const resetContext = service.resetPassword(createPasswordResetClaim(username, password, response.token));
        // expect(resetContext.isAuthenticated).toBeTruthy();

    });

});