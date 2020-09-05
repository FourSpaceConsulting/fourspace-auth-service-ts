import { AuthenticationServiceBuilder } from '../src/service/impl/authentication-service-builder';
import { PrincipalDao } from '../src/dao/principal-dao';
import { AuthToken, AuthTokenSecure, TokenType } from '../src/domain/auth-token';
import { Principal } from '../src/domain/principal';
import { createPasswordClaim, createTokenClaim, createPasswordResetClaim } from '../src/domain/auth-claim';
import { TokenDao } from '../src/dao/token-dao';
import { PrincipalDaoDemo } from '../src/dao/demo/principal-dao-demo';
import moment from 'moment';

describe('Test Service', () => {

    // Mock the dao objects
    const PrincipalDaoMocker = jest.fn<PrincipalDao<Principal>, [Principal]>((principal) => ({
        getPrincipal: jest.fn((key) => Promise.resolve(principal.username === key ? principal : null)),
        savePrincipal: jest.fn()
    }));
    const TokenDaoMocker = jest.fn<TokenDao<Principal>, [AuthTokenSecure<Principal>]>((testToken) => ({
        getToken: jest.fn((key) => Promise.resolve(testToken.key === key ? testToken : null)),
        saveToken: jest.fn(),
    }));

    // get a valid test token
    function getTestToken(): AuthToken<Principal> {
        const testUser = { username: 'testUser@test.com', encryptedPassword: '' };
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
        const encryptedPassword = '$argon2id$v=19$m=65536,t=2,p=1$63rP0KVWybD9jDS5vCqlLA$2v8XhYF9m/y0yPMIese5IS7FxDBwT1XwjHJ0xzg8thE';
        const testPrincipal = { username, encryptedPassword };
        const testToken = getTestToken();
        const testPasswordClaim = createPasswordClaim(username, password);
        // act
        const mockPrincipalDao = new PrincipalDaoMocker(testPrincipal);
        const mockTokenDao = new TokenDaoMocker(testToken);
        const service = new AuthenticationServiceBuilder()
            .setPrincipalDao(mockPrincipalDao)
            .setTokenDao(mockTokenDao)
            .buildAuthenticationManager();
        const context = await service.verifyPasswordClaim(testPasswordClaim);
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
        const encryptedPassword = '$argon2id$v=19$m=65536,t=2,p=1$63rP0KVWybD9jDS5vCqlLA$2v8XhYF9m/y0yPMIese5IS7FxDBwT1XwjHJ0xzg8thE';
        const testPrincipal = { username, encryptedPassword };
        const testPasswordClaim = createPasswordClaim(username, password);
        // act
        const service = new AuthenticationServiceBuilder()
            .setPrincipalDao(new PrincipalDaoDemo([testPrincipal]))
            .buildAuthenticationManager();
        const passwordContext = await service.verifyPasswordClaim(testPasswordClaim);
        const newToken = await service.createUserToken(passwordContext.principal);
        const tokenContext = await service.verifyTokenClaim(createTokenClaim(newToken));
        // assert
        expect(passwordContext.isAuthenticated).toBeTruthy();
        expect(passwordContext.principal).toEqual(testPrincipal);
        expect(tokenContext.isAuthenticated).toBeTruthy();
        expect(tokenContext.principal).toEqual(testPrincipal);
    });

    test('Test service reset password', async () => {
        // arrange
        const username = 'testUser@test.com';
        const newPassword = 'testpassword';
        const testPrincipal = { username, encryptedPassword: '' };
        const newPasswordClaim = createPasswordClaim(username, newPassword);
        // act
        const service = new AuthenticationServiceBuilder()
            .setPrincipalDao(new PrincipalDaoDemo([testPrincipal]))
            .buildAuthenticationManager();
        const response = await service.requestResetPassword({ username, origin: 'Test' });
        const resetSuccess = await service.resetPassword(createPasswordResetClaim(username, response.encodedToken), newPassword);
        const passwordContext = await service.verifyPasswordClaim(newPasswordClaim);
        // assert
        expect(response.success).toBeTruthy();
        expect(resetSuccess).toBeTruthy();
        expect(passwordContext.isAuthenticated).toBeTruthy();
        expect(passwordContext.principal.username).toEqual(testPrincipal.username);
        expect(passwordContext.principal.encryptedPassword).not.toBeNull();
        expect(passwordContext.principal.encryptedPassword).not.toBeUndefined();
        expect(passwordContext.principal.encryptedPassword).not.toEqual('');
        expect(passwordContext.principal.encryptedPassword).not.toEqual(newPassword);

    });

});