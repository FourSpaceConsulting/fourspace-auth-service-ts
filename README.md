# `fourspace-auth-service-ts`

> Server side authentication services for web APIs 

## Features

- Secure authentication using state of the art hashing
- Token strategy for API user authentication
- Authentication lifecycle management (user registration, password reset, token expiry)
- Generic services to accomodate application specific user info
- Flexible service interfaces for bespoke behaviour
- Simple to plug in to express server middleware

## Usage

Default implementation requires supply of two Data Access Object (DAO) implementations, and a messaging service implementation.
 - PrincipalDao to look up users (e.g. from DB or other source)
 - TokenDao to look up/store authentication tokens
 - PrincipalMessageService to send links for registration and password reset.

For demo purposes, basic in memory DAO implementations are included, as well as a message service which just writes to the console.

Use the service builder class to create the authentication service. For the default service, simply supply the required implementations.

`AuthenticationServiceBuilder`

```js
import { AuthenticationServiceBuilder, PrincipalDaoDemo, createPasswordClaim } from 'fourspace-auth-service-ts';

// create a test user
const username = 'testUser@test.com';
const password = 'testpassword';
const passwordHash = '$argon2id$v=19$m=65536,t=2,p=1$63rP0KVWybD9jDS5vCqlLA$2v8XhYF9m/y0yPMIese5IS7FxDBwT1XwjHJ0xzg8thE';
const principal = { username, passwordHash };

// create the default service
const service = new AuthenticationServiceBuilder()
    .setPrincipalDao(new PrincipalDaoDemo([principal]))
    .buildAuthenticationManager();

// use the service to authenticate a username/password
const passwordClaim = createPasswordClaim(username, password);
const context = await service.verifyPasswordClaim(passwordClaim);
if (context.isAuthenticated) {
  console.log('Authenticated with principal:', context.principal);
} else {
  console.log('Failed to authenticate:', context.errorMessage);
}
```

## API

`AuthenticationService<P>`
P is a generic for the user Principal type returned by the supplied DAO services

```js
  verifyPasswordClaim(claim: AuthPasswordClaim): Promise<UserSecurityContext<P>>;
```
* Verify a username/password pair for login. Returns the security context for that user

```js
  requestResetPassword(resetRequest: ResetRequest): UserSecurityContext<P>;
```
* Request a password reset. This will generate a reset token for the user and send a reset message via the message service.

```js
  resetPassword(claim: AuthPasswordResetClaim): UserSecurityContext<P>;
```
* Reset the password for a user. The claim must contain a valid reset token

```js
  verifyTokenClaim(claim: AuthTokenClaim): Promise<UserSecurityContext<P>>;
```
```js
  createUserToken(context: UserSecurityContext<P>): Promise<string>;
```


## Install

```sh
npm install fourspace-auth-service-ts
```

## Credits

## License

[MIT](LICENSE)