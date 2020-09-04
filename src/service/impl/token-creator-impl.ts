import { TokenCreator } from "../token-creator";
import { SecureHash } from "./../secure-hash";
import { RandomStringGenerator } from "./../random-string-generator";
import { DateProvider } from "./../date-provider";
import { AuthToken, TokenType } from "../../domain/auth-token";
import { TokenKeyCreator } from "./../token-key-creator";
import { UserSecurityContext } from "../../domain/security-context";

/**
 * Token creator implementation
 */
export class TokenCreatorImpl<P> implements TokenCreator<P> {
  private readonly _secureHash: SecureHash;
  private readonly _randomStringGenerator: RandomStringGenerator;
  private readonly _tokenKeyCreator: TokenKeyCreator<P>;
  private readonly _dateProvider: DateProvider;
  private readonly _tokenInputLength: number;

  /**
   * Construct the token creator
   *
   * @param secureHash
   * @param randomStringGenerator
   * @param dateProvider
   * @param tokenInputLength
   */
  constructor(
    _tokenKeyCreator: TokenKeyCreator<P>,
    secureHash: SecureHash,
    randomStringGenerator: RandomStringGenerator,
    dateProvider: DateProvider,
    tokenInputLength: number
  ) {
    this._tokenKeyCreator = _tokenKeyCreator;
    this._secureHash = secureHash;
    this._randomStringGenerator = randomStringGenerator;
    this._dateProvider = dateProvider;
    this._tokenInputLength = tokenInputLength;
  }

  public async createAuthenticationToken(
    context: UserSecurityContext<P>
  ): Promise<AuthToken<P>> {
    const user = context.principal;
    const key = await this._tokenKeyCreator.createKey(context);
    const plainToken = await this._randomStringGenerator.generateRandom(
      this._tokenInputLength
    );
    const hashToken = await this._secureHash.createHash(plainToken);
    const created = this._dateProvider.getDateTime();
    const expiry = this._dateProvider.getDateTime();
    return {
      tokenType: TokenType.UserToken,
      key,
      plainToken,
      hashToken,
      user,
      created,
      expiry
    };
  }
}
