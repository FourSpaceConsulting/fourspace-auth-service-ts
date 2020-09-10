import { SecureHashImpl } from '../src/service/impl/secure-hash-impl';
import { UserAuthenticatorImpl } from '../src/service/impl/user-authenticator-impl';
import { PrincipalDao } from '../src/dao/principal-dao';
import { Principal } from '../src/domain/principal';
import { createPasswordAuthClaim } from '../src/domain/auth-claim';

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

});