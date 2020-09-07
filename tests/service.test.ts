import { AuthenticationServiceBuilder } from '../src/service/impl/authentication-service-builder';
import { PrincipalDao } from '../src/dao/principal-dao';
import { AuthToken, AuthTokenSecure, TokenType } from '../src/domain/auth-token';
import { Principal } from '../src/domain/principal';
import { createPasswordAuthClaim, createAccessTokenAuthClaim, createPasswordResetAuthClaim, createVerifyUserAuthClaim, createRefreshAccessTokenAuthClaim } from '../src/domain/auth-claim';
import { TokenDao } from '../src/dao/token-dao';
import { PrincipalDaoDemo } from '../src/dao/demo/principal-dao-demo';
import moment from 'moment';

describe('Test Service', () => {

    // Mock the dao objects
    const PrincipalDaoMocker = jest.fn<PrincipalDao<Principal>, [Principal]>((principal) => ({
        getPrincipal: jest.fn((key) => Promise.resolve(principal.username === key ? principal : null)),
        savePrincipal: jest.fn(),
        updatePrincipal: jest.fn()
    }));
    const TokenDaoMocker = jest.fn<TokenDao<Principal>, [AuthTokenSecure<Principal>]>((testToken) => ({
        getToken: jest.fn((key) => Promise.resolve(testToken.key === key ? testToken : null)),
        saveToken: jest.fn(),
    }));

    test('Test default builder mock dao password verify', async () => {
        // arrange
        const username = 'testUser@test.com';
        const password = 'testpassword';
        const encryptedPassword = '$argon2id$v=19$m=65536,t=2,p=1$63rP0KVWybD9jDS5vCqlLA$2v8XhYF9m/y0yPMIese5IS7FxDBwT1XwjHJ0xzg8thE';
        const testPrincipal = { username, encryptedPassword, isVerified: true };
        const testPasswordClaim = createPasswordAuthClaim(username, password);
        // act
        const mockPrincipalDao = new PrincipalDaoMocker(testPrincipal);
        const mockTokenDao = new TokenDaoMocker(null);
        const service = new AuthenticationServiceBuilder()
            .setPrincipalDao(mockPrincipalDao)
            .setTokenDao(mockTokenDao)
            .buildAuthenticationManager();
        const context = await service.authenticatePasswordClaim(testPasswordClaim);
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
        const testPrincipal = { username, encryptedPassword, isVerified: true };
        const testPasswordClaim = createPasswordAuthClaim(username, password);
        // act
        const service = new AuthenticationServiceBuilder()
            .setPrincipalDao(new PrincipalDaoDemo([testPrincipal]))
            .buildAuthenticationManager();
        const passwordContext = await service.authenticatePasswordClaim(testPasswordClaim);
        const newToken = await service.createAccessToken(passwordContext.principal);
        const tokenContext = await service.authenticateAccessTokenClaim(createAccessTokenAuthClaim(newToken.accessToken));
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
        const testPrincipal = { username, encryptedPassword: '', isVerified: true };
        const newPasswordClaim = createPasswordAuthClaim(username, newPassword);
        // act
        const service = new AuthenticationServiceBuilder()
            .setPrincipalDao(new PrincipalDaoDemo([testPrincipal]))
            .buildAuthenticationManager();
        const response = await service.requestResetPassword({ username, origin: 'Test' });
        const resetAuth = await service.authenticatePasswordResetClaim(createPasswordResetAuthClaim(username, response.encodedToken));
        const resetSuccess = await service.resetPassword(resetAuth.authToken.principal, newPassword);
        const passwordContext = await service.authenticatePasswordClaim(newPasswordClaim);
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


    test('Test service full workflow', async () => {
        // arrange
        const username = 'testUser@test.com';
        const initialPassword = 'testpassword';
        const newPassword = 'newpassword';
        const testPrincipal = { username, encryptedPassword: '', isVerified: false };
        const newPasswordClaim = createPasswordAuthClaim(username, newPassword);
        // act and assert
        const service = new AuthenticationServiceBuilder()
            .buildAuthenticationManager();
        // 1 - Register new user
        const registerResponse = await service.registerUser({ newPrincipal: testPrincipal, password: initialPassword });
        expect(registerResponse.isSuccess).toBeTruthy();
        // 2 - verify user
        const verifyAuth = await service.authenticateVerifyClaim(createVerifyUserAuthClaim(registerResponse.encodedToken));
        expect(verifyAuth.isAuthenticated).toBeTruthy();
        const verifySuccess = await service.verifyUser(verifyAuth.authToken.principal);
        expect(verifySuccess).toBeTruthy();
        // 3 - log in and get tokens
        const initialPasswordAuth = await service.authenticatePasswordClaim(createPasswordAuthClaim(username, initialPassword));
        expect(initialPasswordAuth.isAuthenticated).toBeTruthy();
        const firstAccess = await service.createAccessToken(initialPasswordAuth.principal);
        // 4 - use access tokens for resources
        // 5 - refresh access token
        const refreshAuth = await service.authenticateTokenRefreshClaim(createRefreshAccessTokenAuthClaim(firstAccess.refreshToken));
        expect(refreshAuth.isAuthenticated).toBeTruthy();
        const secondAccess = await service.refreshAccessToken(refreshAuth.authToken);
        // 6 - active logout
        // 7 - access tokens and refresh tokens invalid
        // 8 - request password reset
        // 9 - perform reset
        // 10 - log in fails with old pwd, passes with new one
        const response = await service.requestResetPassword({ username, origin: 'Test' });
        const resetAuth = await service.authenticatePasswordResetClaim(createPasswordResetAuthClaim(username, response.encodedToken));
        const resetSuccess = await service.resetPassword(resetAuth.authToken.principal, newPassword);
        const passwordContext = await service.authenticatePasswordClaim(newPasswordClaim);
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