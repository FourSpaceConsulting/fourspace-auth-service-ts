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
import { createAuthenticationRoutes } from '../src/express/auth-routes';
import { AuthHandlerImpl, AuthHandlers } from '../src/express/auth-handlers';
import { AuthController, AuthControllerImpl } from '../src/express/auth-controller';
import { ValidationHandlersImpl } from '../src/express/validation-handlers';
import { AuthExceptionService } from '../src/express/exception-service';
import { RequestUserMapper } from '../src/express/request-user-mapper';
import { RouteConfiguration, ExpressLikeRequestHandler, ExpressLikeRequest, ExpressLikeResponse, ExpressLikeIncomingHttpHeaders, ExpressLikeParamsDictionary } from '../src/express/express-interface';

describe('Test Server Routes', () => {

    // Mock the dao objects
    const ExceptionServiceMock = jest.fn<AuthExceptionService, []>(() => ({
        throwBadRequest: jest.fn(),
        throwForbidden: jest.fn(),
        throwInternalServer: jest.fn(),
        throwUnauthenticated: jest.fn(),
    }));
    const RequestUserMapperMock = jest.fn<RequestUserMapper<Principal>, []>(() => ({
        createNewUser: jest.fn(b => { return { username: b.username } as Principal }),
        validateNewUser: jest.fn().mockReturnValue(true)
    }));
    // Mock the response
    const ResponseMocker = jest.fn<ExpressLikeResponse, [any[]]>(function (jsonList: any[]) {
        return {
            status: jest.fn().mockReturnThis(),
            send: jest.fn().mockReturnThis(),
            json: jest.fn(v => { jsonList.push(v); })
        }
    });


    test('Test register', async () => {
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
        //
        const mockExceptionService = new ExceptionServiceMock();
        const mockUserMapper = new RequestUserMapperMock();
        const authenticationService = new AuthenticationServiceBuilder()
            .setActionMessageService(actionMessageService)
            .setPrincipalDao(principalDao)
            .setTokenDao(tokenDao)
            .buildAuthenticationService();
        const authHandlers: AuthHandlers = new AuthHandlerImpl(authenticationService, mockExceptionService);
        const authController: AuthController = new AuthControllerImpl(authenticationService, mockUserMapper, mockExceptionService);
        const validationHandlers: ValidationHandlersImpl = new ValidationHandlersImpl(mockExceptionService);
        const routes = createAuthenticationRoutes((s) => s, authHandlers, validationHandlers, authController);
        const routeMap: Map<string, RouteConfiguration> = routes.reduce((m, o) => { m.set(o.path, o); return m; }, new Map());
        // act and assert
        // 1 - Register new user
        await testRegisterStep(routeMap);
        // 2 - verify
        await testVerifyStep(routeMap, actionMessageService);
        // 3 - login
        await testLoginStep(routeMap);

    });

    async function testRegisterStep(routeMap: Map<string, RouteConfiguration>) {
        const request: ExpressLikeRequest = {
            headers: null,
            params: null,
            body: {
                username: 'test@testmail.com',
                password: 'testPassword'
            }
        }
        const mockResponse = new ResponseMocker([]);
        const handlerArray = getHandlerArray(routeMap, '/auth/register');
        await runHandlers(request, mockResponse, handlerArray);
        expect(mockResponse.json).toHaveBeenCalledTimes(1);
        expect(mockResponse.json).toHaveBeenCalledWith(true);
    }

    async function testVerifyStep(routeMap: Map<string, RouteConfiguration>, actionMessageService: ActionMessageServiceDemo<any>) {
        const message = actionMessageService.actionMessages.find(a => a.actionType === ActionType.Verify);
        expect(message).toBeDefined();
        // make request with token in the header
        const request: ExpressLikeRequest = {
            headers: { authorization: message.actionToken },
            params: null,
            body: null
        };
        const mockResponse = new ResponseMocker([]);
        const handlerArray = getHandlerArray(routeMap, '/auth/verify');
        await runHandlers(request, mockResponse, handlerArray);
        expect(mockResponse.json).toHaveBeenCalledTimes(1);
        expect(mockResponse.json).toHaveBeenCalledWith(true);
    }

    async function testLoginStep(routeMap: Map<string, RouteConfiguration>) {
        // make request with token in the header
        const request: ExpressLikeRequest = {
            headers: null,
            params: null,
            body: {
                username: 'test@testmail.com',
                password: 'testPassword'
            }
        };
        const jsonList: any[] = [];
        const mockResponse = new ResponseMocker(jsonList);
        const handlerArray = getHandlerArray(routeMap, '/auth/login');
        await runHandlers(request, mockResponse, handlerArray);
        expect(mockResponse.json).toHaveBeenCalledTimes(1);
        expect(mockResponse.json).toHaveBeenCalledWith(jsonList[0]);
    }


});


function getHandlerArray(routeMap: Map<string, RouteConfiguration>, route: string) {
    const config = routeMap.get(route);
    expect(config).toBeDefined();
    const handlers = config.handler;
    return Array.isArray(handlers) ? handlers as ExpressLikeRequestHandler[] : [handlers as ExpressLikeRequestHandler];
}

function runHandlers(req: ExpressLikeRequest, res: ExpressLikeResponse, handlers: ExpressLikeRequestHandler[]): Promise<void> {
    let promises: (Promise<void> | void)[] = [];
    // create next functions from list of handlers
    let nextFns = handlers.map((handler, i) =>
        () => {
            const next = (i + 1) < nextFns.length ? nextFns[i + 1] : () => { }
            promises.push(handler(req, res, next));
        }
    );
    // run first handler
    if (nextFns.length > 0) {
        nextFns[0]();
    }
    // resolve promises
    const buildResolveNext = (index: number) => {
        return (): Promise<void> => {
            if (index < promises.length) {
                let currentPromise = promises[index];
                return currentPromise != null ? (currentPromise as Promise<void>).then(buildResolveNext(index + 1)) : Promise.resolve();
            }
        }
    }
    return promises.length > 0 ? buildResolveNext(0)() : Promise.resolve();
}
