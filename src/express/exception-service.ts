export interface AuthExceptionService {
    throwUnauthenticated(message?: string): void;
    throwForbidden(message?: string): void;
    throwBadRequest(message?: string): void;
    throwInternalServer(message?: string): void;
}
