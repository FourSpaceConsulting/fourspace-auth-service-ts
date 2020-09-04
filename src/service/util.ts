import moment from "moment";
import { AuthToken } from "../domain/auth-token";
import { TokenInfo } from "../domain/token-info";

export const getTokenInfo = (t: AuthToken<any>): TokenInfo => ({
  tokenKey: t.key,
  tokenValue: t.plainToken,
  expire: moment(t.created).unix()
});
