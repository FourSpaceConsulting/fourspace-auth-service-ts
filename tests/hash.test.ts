import { SecureHashImpl } from '../src/service/impl/secure-hash-impl';

describe('Test Secure Hash Implementation', () => {

    const plainToken = 'RWyzKLK2aQqTVnSOD_NdsY-bbY6b656oqkImx2H62Bq1M7r_ea';
    const hashToken = '$argon2id$v=19$m=65536,t=2,p=1$lu1rT+rmvqkp0BhPRH2r9A$kHkGkE3pnZT7sAy3Y7V263hWGvqvcNaAi37rnzHfGdM';

    test('Test Verify Existing Hash', async () => {
        // arrange
        const hash = new SecureHashImpl();
        // act
        const isMatch = await hash.verifyHash(plainToken, hashToken);
        // assert
        expect(isMatch).toBeTruthy();
    });

    test('Test Verify New Hash', async () => {
        // arrange
        const hash = new SecureHashImpl();
        // act
        const newHash = (await hash.createHash(plainToken)).toString();
        const isMatch = await hash.verifyHash(plainToken, newHash);
        // assert
        expect(isMatch).toBeTruthy();
    });

    test('Test Verify Bad Token', async () => {
        // arrange
        const hash = new SecureHashImpl();
        const badToken = 'ZWyzKLK2aQqTVnSOD_NdsY-bbY6b656oqkImx2H62Bq1M7r_ea';
        // act
        const isMatch = await hash.verifyHash(badToken, hashToken);
        // assert
        expect(isMatch).toBeFalsy();
    });

    test('Test Verify Bad Hash', async () => {
        // arrange
        const hash = new SecureHashImpl();
        const badHash = '$argon2id$v=19$m=65536,t=2,p=1$lu1rT+rmvqkp0AhPR42r9A$kHkGkE3pnZT7sAy3Y7V263hWGvqvcNaAi37rnzHfGdM';
        // act
        const isMatch = await hash.verifyHash(plainToken, badHash);
        // assert
        expect(isMatch).toBeFalsy();
    });

});