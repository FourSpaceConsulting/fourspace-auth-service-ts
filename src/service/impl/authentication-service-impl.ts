import { AuthenticationService } from "../authentication-service";
import {
  AuthPasswordClaim,
  AuthTokenClaim,
  AuthPasswordResetClaim
} from "../../domain/auth-claim";
import { UserSecurityContext } from "../../domain/security-context";
import { UserAuthenticator } from "../user-authenticator";
import { TokenCreator } from "../token-creator";
import { TokenAuthenticator } from "../token-authenticator";
import { TokenEncoder } from "../token-encoder";
import { TokenDao } from "../../dao/token-dao";
import { ResetRequest, ResetRequestResponse } from "../../domain/reset-request";
import { getTokenInfo } from "../util";

export class AuthenticationServiceImpl<P> implements AuthenticationService<P> {
  private _userAuthenticator: UserAuthenticator<P>;
  private _tokenAuthenticator: TokenAuthenticator<P>;
  private _tokenCreator: TokenCreator<P>;
  private _tokenEncoder: TokenEncoder;
  private _tokenDao: TokenDao<P>;

  constructor(
    userAuthenticator: UserAuthenticator<P>,
    tokenAuthenticator: TokenAuthenticator<P>,
    tokenCreator: TokenCreator<P>,
    tokenEncoder: TokenEncoder,
    tokenDao: TokenDao<P>
  ) {
    if (tokenDao == null) throw new Error("TokenDao is null");
    this._userAuthenticator = userAuthenticator;
    this._tokenAuthenticator = tokenAuthenticator;
    this._tokenCreator = tokenCreator;
    this._tokenEncoder = tokenEncoder;
    this._tokenDao = tokenDao;
  }

  public verifyPasswordClaim(
    claim: AuthPasswordClaim
  ): Promise<UserSecurityContext<P>> {
    // authenticate user claim
    return this._userAuthenticator.authenticateUser(claim);
  }

  public verifyTokenClaim(
    claim: AuthTokenClaim
  ): Promise<UserSecurityContext<P>> {
    // authenticate token claim
    return this._tokenAuthenticator.authenticateToken(claim);
  }

  public async createUserToken(
    context: UserSecurityContext<P>
  ): Promise<string> {
    // create new token
    const token = await this._tokenCreator.createAuthenticationToken(context);
    // persist
    const savedToken = await this._tokenDao.saveToken(token);
    // merge token, as the key may only be set on persistence
    const mergedToken = { ...token, key: savedToken.key };
    // encode and return
    return this._tokenEncoder.encode(getTokenInfo(mergedToken));
  }

  public requestResetPassword(
    resetRequest: ResetRequest
  ): ResetRequestResponse {
    //    resetRequest.username;
    throw new Error("Method not implemented.");
  }

  resetPassword(claim: AuthPasswordResetClaim): UserSecurityContext<P> {
    throw new Error("Method not implemented.");
  }
}
