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

export class ValidationHandlersImpl implements AuthValidationHandlers {
    private _validateInitialUsernameAndPassword: ExpressLikeRequestHandler;
    private _validateUsername: ExpressLikeRequestHandler;
    private _validatePassword: ExpressLikeRequestHandler;

    constructor(ex: AuthExceptionService) {
        this._setInitialUsernameAndPasswordHandler(ex);
        this._setUsernameHandler(ex);
        this._setPasswordHandler(ex);
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

    private _setInitialUsernameAndPasswordHandler(ex: AuthExceptionService) {
        this._validateInitialUsernameAndPassword = async (req, _, next) => {
            // validate
            const username = UsernameGetter(req);
            const password = PasswordGetter(req);
            if (!isValidUsername(username) || !isValidUsername(password)) {
                ex.throwBadRequest('Invalid username or password');
            }
            // next
            next();
        };
    }

    private _setUsernameHandler(ex: AuthExceptionService) {
        this._validateUsername = async (req, _, next) => {
            // validate
            const username = UsernameGetter(req);
            if (!isValidUsername(username)) {
                ex.throwBadRequest('Invalid username');
            }
            next();
        };
    }

    private _setPasswordHandler(ex: AuthExceptionService) {
        this._validatePassword = async (req, _, next) => {
            // validate
            const password = PasswordGetter(req);
            if (!isValidUsername(password)) {
                ex.throwBadRequest('Invalid password');
            }
        };
    }

    //#endregion
}

function isValidUsername(username: string) {
    return username != null && username.trim() !== '';
}
