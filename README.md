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

## Workflow

* Register user (user name and password) - create user and verify token
* Message user with verify link - user is verfied and log in can take place
* Log in - access token and refresh token (and remember me if requested) created 

* API calls made using access token
* Refresh access - when access token is close to expiry/expired, only the refresh token can create new access token 
  1) verify refresh token
  2) create new access token and new refresh token

2 scenarios:
log in user name/password - receive access and refresh
access expired - supply refresh token to get new access/refresh pair (refresh token has updated)

Access token - valid for ATE mins
refresh token - valid for RTE hours

continuous website use - 
constant usage of access token
every ATE mins a new access token is produced and refresh token hash and expiry is updated
when usage stops without logout, refresh token stays valid for between RTE-ATE and RTE mins
once RT is expired, new log in is required (unless a remember me token exists)

When AT is refreshed, new AT is created (old AT may remain active or be deleted, not sure yet) and modified RT is returned
AT -> RT link required if we want AT to be verified with RT and if we want AT to be deleted
reset token key can be associated to many access tokens if we don't delete active token

## Tokens

There are multiple tokens used to authenticate certain activities
* Verify Token - verifies the user (email registration workflow)
* Access Token - allows access to the API (short lived)
* Refresh Token - allows creation of a new access token (invalidating associated token if not already expired)
* Reset Token - allows a user to reset a forgotten password (email reset workflow)
* Remember Token - token for remaining signed in despite inactivity (no expiry)

## Service Implementations

TokenDao
Verify user - only one token per user at any time
1) create verification token (deletes all other verify tokens for this user)
2) send to user
3) user clicks link
4) token authenticated and then deleted (can only verify once with this token)
5) user updated

if at 4) authenticated and another API call creates verification token, then current token is already deleted

Reset password
1) create reset token (deletes all other reset tokens for this user)
2) send to user
3) user follows link
4) token authenticated and deleted (can only be attempted once with this token)
5) password reset

if (before 4) another API calls create reset token, then token is no longer valid
if at (4) authenticated and another API call creates reset token, then current token is already deleted


## Install

```sh
npm install fourspace-auth-service-ts
```

## Credits

## License

[MIT](LICENSE)