import { AuthenticationServiceBuilder } from '../src/service/impl/authentication-service-builder';
import { PrincipalDao } from '../src/dao/principal-dao';
import { AuthToken, AuthTokenSecure, TokenType } from '../src/domain/auth-token';
import { Principal } from '../src/domain/principal';
import { createPasswordAuthClaim, createAccessTokenAuthClaim, createPasswordResetAuthClaim, createVerifyUserAuthClaim, createRefreshAccessTokenAuthClaim } from '../src/domain/auth-claim';
import { TokenDao } from '../src/dao/token-dao';
import { PrincipalDaoDemo } from '../src/dao/demo/principal-dao-demo';
import { ActionMessageServiceDemo } from '../src/actions/demo/action-message-service-demo';
import { ActionType } from '../src/domain/action-message';
import { TokenDaoDemo } from '../src/dao/demo/token-dao-demo';

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
        updateToken: jest.fn(),
        deleteTokens: jest.fn()
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
            .buildAuthenticationService();
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
            .buildAuthenticationService();
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
        const username = 'testServiceReset@test.com';
        const newPassword = 'testpassword';
        const testPrincipal = { username, encryptedPassword: '', isVerified: true };
        const newPasswordClaim = createPasswordAuthClaim(username, newPassword);
        // act
        const service = new AuthenticationServiceBuilder()
            .setPrincipalDao(new PrincipalDaoDemo([testPrincipal]))
            .buildAuthenticationService();
        const response = await service.requestResetPassword({ username, origin: 'Test' });
        const resetAuth = await service.authenticatePasswordResetClaim(createPasswordResetAuthClaim(response.encodedToken));
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
        const username = 'testFullWorkflow@test.com';
        const initialPassword = 'testpassword';
        const newPassword = 'newpassword';
        const testPrincipal = { username, encryptedPassword: '', isVerified: false };
        const initialPasswordClaim = createPasswordAuthClaim(username, initialPassword);
        const newPasswordClaim = createPasswordAuthClaim(username, newPassword);
        const actionMessageService = new ActionMessageServiceDemo();
        const principalDao = new PrincipalDaoDemo<Principal>([]);
        const tokenDao = new TokenDaoDemo();
        // act and assert
        const service = new AuthenticationServiceBuilder()
            .setActionMessageService(actionMessageService)
            .setPrincipalDao(principalDao)
            .setTokenDao(tokenDao)
            .buildAuthenticationService();
        // 1 - Register new user and fail log in if not verified
        const registerResponse = await service.createUserAndSendVerificationMessage({ newPrincipal: testPrincipal, password: initialPassword });
        expect(registerResponse.isSuccess).toBeTruthy();
        expect(actionMessageService.actionMessages[0].actionType).toBe(ActionType.Verify)
        expect((await principalDao.getPrincipal(username)).isVerified).toBeFalsy();
        const unverifiedPasswordAuth = await service.authenticatePasswordClaim(initialPasswordClaim);
        expect(unverifiedPasswordAuth.isAuthenticated).toBeFalsy();
        expect(unverifiedPasswordAuth.principal).toBeNull();
        // 2 - verify user
        const verifyAuth = await service.authenticateVerifyClaim(createVerifyUserAuthClaim(registerResponse.encodedToken));
        expect(verifyAuth.isAuthenticated).toBeTruthy();
        const verifySuccess = await service.verifyUser(verifyAuth.authToken.principal);
        expect(verifyAuth.authToken.principal).toBeDefined();
        expect(verifySuccess).toBeTruthy();
        // 3 - log in and get tokens
        const initialPasswordAuth = await service.authenticatePasswordClaim(initialPasswordClaim);
        expect(initialPasswordAuth.principal.username).toBe(testPrincipal.username);
        expect(initialPasswordAuth.isAuthenticated).toBeTruthy();
        const firstAccess = await service.createAccessToken(initialPasswordAuth.principal);
        // 4 - use access tokens for resources
        const resourceAuth = await service.authenticateAccessTokenClaim(createAccessTokenAuthClaim(firstAccess.accessToken));
        expect(resourceAuth.isAuthenticated).toBeTruthy();
        expect(resourceAuth.principal.username).toBe(testPrincipal.username);
        // 5 - refresh access token and check that refresh is no longer valid (can only refresh once with that token)
        const refreshAuth = await service.authenticateTokenRefreshClaim(createRefreshAccessTokenAuthClaim(firstAccess.refreshToken));
        expect(refreshAuth.isAuthenticated).toBeTruthy();
        const secondAccess = await service.refreshAccessToken(refreshAuth.authToken);
        const invalidRefreshAuth = await service.authenticateTokenRefreshClaim(createRefreshAccessTokenAuthClaim(firstAccess.refreshToken));
        expect(invalidRefreshAuth.isAuthenticated).toBeFalsy();
        // 6 - active revoke of refresh (logout)
        const logoutAuth = await service.authenticateTokenRefreshClaim(createRefreshAccessTokenAuthClaim(secondAccess.refreshToken));
        expect(logoutAuth.isAuthenticated).toBeTruthy();
        const revoked = await service.revokeRefreshToken(logoutAuth.authToken);
        expect(revoked).toBeTruthy();
        // 7 - access tokens and refresh tokens invalid
        const revokedRefreshAuth = await service.authenticateTokenRefreshClaim(createRefreshAccessTokenAuthClaim(secondAccess.refreshToken));
        const revokedFirstAccessAuth = await service.authenticateAccessTokenClaim(createAccessTokenAuthClaim(firstAccess.accessToken));
        const revokedSecondAccessAuth = await service.authenticateAccessTokenClaim(createAccessTokenAuthClaim(secondAccess.accessToken));
        expect(revokedRefreshAuth.isAuthenticated).toBeFalsy();
        expect(revokedFirstAccessAuth.isAuthenticated).toBeFalsy();
        expect(revokedSecondAccessAuth.isAuthenticated).toBeFalsy();
        // 8 - request password reset
        const resetResponse = await service.requestResetPassword({ username, origin: 'Test' });
        expect(resetResponse.success).toBeTruthy();
        // 9 - perform reset
        const resetAuth = await service.authenticatePasswordResetClaim(createPasswordResetAuthClaim(resetResponse.encodedToken));
        expect(resetAuth.isAuthenticated).toBeTruthy();
        const resetSuccess = await service.resetPassword(resetAuth.authToken.principal, newPassword);
        expect(resetSuccess).toBeTruthy();
        // 10 - log in fails with old pwd, passes with new one
        const obsoletePasswordAuth = await service.authenticatePasswordClaim(initialPasswordClaim);
        const newPasswordAuth = await service.authenticatePasswordClaim(newPasswordClaim);
        expect(obsoletePasswordAuth.isAuthenticated).toBeFalsy();
        expect(newPasswordAuth.isAuthenticated).toBeTruthy();
        // 11 - generate new tokens
        const lastAccess = await service.createAccessToken(newPasswordAuth.principal);
        const lastAuth = await service.authenticateAccessTokenClaim(createAccessTokenAuthClaim(lastAccess.accessToken));
        expect(lastAuth.isAuthenticated).toBeTruthy();
        expect(lastAuth.principal.username).toBe(testPrincipal.username);
        // assert messages
        console.log(await tokenDao.getAll());
        expect(actionMessageService.actionMessages.length).toBe(2)
        expect(actionMessageService.actionMessages[0].actionType).toBe(ActionType.Verify)
        expect(actionMessageService.actionMessages[1].actionType).toBe(ActionType.PasswordReset)
    });


});