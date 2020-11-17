import { SecureHashImpl } from '../src/service/impl/secure-hash-impl';
import { UserAuthenticatorImpl } from '../src/service/impl/user-authenticator-impl';
import { PrincipalDao } from '../src/dao/principal-dao';
import { Principal } from '../src/domain/principal';
import { createPasswordAuthClaim } from '../src/domain/auth-claim';
import { DateProvider } from '../src/service/date-provider';
import { ExpiryCheckerImpl } from '../src/service/impl/expiry-checker-impl';
import moment from 'moment';
import { TokenType } from '../src/domain/auth-token';

describe('Test Expiry Checker', () => {

    // Mock a data provider
    const DateProviderMocker = jest.fn<DateProvider, [Date]>((date) => ({
        getDateTime: jest.fn(() => date),
        saveToken: jest.fn(),
    }));

    // create an expiry checker
    const TestVerifyExpiry = 60;
    const TestPasswordResetExpiry = 10;
    const TestAccessExpiry = 30;
    const TestRefreshExpiry = 180;
    function createExpiryChecker(testDate: Date) {
        return new ExpiryCheckerImpl(new DateProviderMocker(testDate));
    }
    // util for adding minutes to a date
    function addMinutes(from: Date, minutes: number): Date {
        return moment(from)
            .add(minutes, 'minute')
            .toDate();
    }

    test('Test Pass', async () => {
        // arrange
        const testDate = moment(Date.UTC(2020, 1, 1, 14, 20, 20)).toDate();
        const expiryDate1 = moment(Date.UTC(2020, 1, 1, 14, 20, 40)).toDate();
        const expiryDate2 = addMinutes(testDate, 1);
        // act
        const checker = createExpiryChecker(testDate);
        const isValid1 = checker.isValid(expiryDate1);
        const isValid2 = checker.isValid(expiryDate2);
        // assert
        expect(isValid1).toBeTruthy();
        expect(isValid2).toBeTruthy();
    });

    test('Test Fail', async () => {
        // arrange
        //   ---- c -- e -----
        const testDate = moment(Date.UTC(2020, 1, 1, 14, 20, 20)).toDate();
        const expiryDate1 = moment(Date.UTC(2020, 1, 1, 14, 20, 10)).toDate();
        const expiryDate2 = addMinutes(testDate, -10);
        // act
        const checker = createExpiryChecker(testDate);
        const isValid1 = checker.isValid(expiryDate1);
        const isValid2 = checker.isValid(expiryDate2);
        // assert
        expect(isValid1).toBeFalsy();
        expect(isValid2).toBeFalsy();
    });

});