import { TokenType } from '../../domain/auth-token';
import { DateProvider } from '../date-provider';
import { ExpiryChecker } from '../expiry-checker';
import { ExpiryConfig } from './token-creator-impl';
import moment from 'moment';

/**
 * Check the token date is not past expiry
 */
export class ExpiryCheckerImpl implements ExpiryChecker {
    private readonly _dateProvider: DateProvider;

    constructor(dateProvider: DateProvider) {
        this._dateProvider = dateProvider;
    }

    public isValid(expiry: Date): boolean {
        return this._dateProvider.getDateTime() < expiry;
    }
}
