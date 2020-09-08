import { CreateBodyGetter, ExpressLikeRouteHandler } from './express-util';
import { ExceptionService } from './exception-service';

// Authentication parameter names
export const UsernameParameter = 'username';
export const PasswordParameter = 'password';

// Request body getters
export const UsernameGetter = CreateBodyGetter(UsernameParameter);
export const PasswordGetter = CreateBodyGetter(PasswordParameter);

/**
 * These are the express handlers for validating values in the request
 */
export interface ValidationHandlers {
    readonly validateInitialUsernameAndPassword: ExpressLikeRouteHandler;
    readonly validateUsername: ExpressLikeRouteHandler;
    readonly validatePassword: ExpressLikeRouteHandler;
}

export class ValidationHandlersImpl implements ValidationHandlers {
    private _validateInitialUsernameAndPassword: ExpressLikeRouteHandler;
    private _validateUsername: ExpressLikeRouteHandler;
    private _validatePassword: ExpressLikeRouteHandler;

    constructor(ex: ExceptionService) {
        this._setInitialUsernameAndPasswordHandler(ex);
        this._setUsernameHandler(ex);
        this._setPasswordHandler(ex);
    }

    /**
     * Getter initialUsernameAndPassword
     * @return {ExpressLikeRouteHandler}
     */
    public get validateInitialUsernameAndPassword(): ExpressLikeRouteHandler {
        return this._validateInitialUsernameAndPassword;
    }

    /**
     * Getter validateUsername
     * @return {ExpressLikeRouteHandler}
     */
    public get validateUsername(): ExpressLikeRouteHandler {
        return this._validateUsername;
    }

    /**
     * Getter validatePassword
     * @return {ExpressLikeRouteHandler}
     */
    public get validatePassword(): ExpressLikeRouteHandler {
        return this._validatePassword;
    }

    //#endregion
    //#region --- Create the handlers

    private _setInitialUsernameAndPasswordHandler(ex: ExceptionService) {
        this._validateInitialUsernameAndPassword = async (req, _, next) => {
            // validate
            const username = UsernameGetter(req);
            const password = PasswordGetter(req);
            if (!isValidUsername(username) || isValidUsername(password)) {
                ex.throwBadRequest('Invalid username or password');
            }
            // next
            next();
        };
    }

    private _setUsernameHandler(ex: ExceptionService) {
        this._validateUsername = async (req, _, next) => {
            // validate
            const username = UsernameGetter(req);
            if (!isValidUsername(username)) {
                ex.throwBadRequest('Invalid username');
            }
            next();
        };
    }

    private _setPasswordHandler(ex: ExceptionService) {
        this._validatePassword = async (req, _, next) => {
            // validate
            const password = PasswordGetter(req);
            if (isValidUsername(password)) {
                ex.throwBadRequest('Invalid password');
            }
        };
    }

    //#endregion
}

function isValidUsername(username: string) {
    return username != null && username.trim() !== '';
}
