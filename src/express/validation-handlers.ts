import { ExpressLikeRequestHandler } from './express-interface';
import { AuthExceptionService } from './exception-service';
import { createBodyGetter } from './request-util';

// Authentication parameter names
export const UsernameParameter = 'username';
export const PasswordParameter = 'password';

// Request body getters
export const UsernameGetter = createBodyGetter(UsernameParameter);
export const PasswordGetter = createBodyGetter(PasswordParameter);

/**
 * These are the express handlers for validating values in the request
 */
export interface AuthValidationHandlers {
    readonly validateInitialUsernameAndPassword: ExpressLikeRequestHandler;
    readonly validateUsername: ExpressLikeRequestHandler;
    readonly validatePassword: ExpressLikeRequestHandler;
}

type Predicate = (s: string) => boolean;

export class ValidationHandlersImpl implements AuthValidationHandlers {
    private _validateInitialUsernameAndPassword: ExpressLikeRequestHandler;
    private _validateUsername: ExpressLikeRequestHandler;
    private _validatePassword: ExpressLikeRequestHandler;

    constructor(ex: AuthExceptionService, isUsernameValid: Predicate, isPasswordValid: Predicate) {
        this._setInitialUsernameAndPasswordHandler(ex, isUsernameValid, isPasswordValid);
        this._setUsernameHandler(ex, isUsernameValid);
        this._setPasswordHandler(ex, isPasswordValid);
    }

    /**
     * Getter initialUsernameAndPassword
     * @return {ExpressLikeRequestHandler}
     */
    public get validateInitialUsernameAndPassword(): ExpressLikeRequestHandler {
        return this._validateInitialUsernameAndPassword;
    }

    /**
     * Getter validateUsername
     * @return {ExpressLikeRequestHandler}
     */
    public get validateUsername(): ExpressLikeRequestHandler {
        return this._validateUsername;
    }

    /**
     * Getter validatePassword
     * @return {ExpressLikeRequestHandler}
     */
    public get validatePassword(): ExpressLikeRequestHandler {
        return this._validatePassword;
    }

    //#endregion
    //#region --- Create the handlers

    private _setInitialUsernameAndPasswordHandler(
        ex: AuthExceptionService,
        isUsernameValid: Predicate,
        isPasswordValid: Predicate
    ) {
        this._validateInitialUsernameAndPassword = async (req, _, next) => {
            // validate
            const username = UsernameGetter(req);
            const password = PasswordGetter(req);
            if (!isUsernameValid(username) || !isPasswordValid(password)) {
                ex.throwBadRequest('Invalid username or password');
            }
            // next
            next();
        };
    }

    private _setUsernameHandler(ex: AuthExceptionService, isUsernameValid: Predicate) {
        this._validateUsername = async (req, _, next) => {
            // validate
            const username = UsernameGetter(req);
            if (!isUsernameValid(username)) {
                ex.throwBadRequest('Invalid username');
            }
            next();
        };
    }

    private _setPasswordHandler(ex: AuthExceptionService, isPasswordValid: Predicate) {
        this._validatePassword = async (req, _, next) => {
            // validate
            const password = PasswordGetter(req);
            if (!isPasswordValid(password)) {
                ex.throwBadRequest('Invalid password');
            }
        };
    }

    //#endregion
}
