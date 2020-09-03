import { Principal } from "./principal";
export interface AuthTokenSecure<P> {
  readonly key: string;
  readonly hashToken: string;
  readonly created: Date;
  readonly user: P;
}

export interface AuthToken<P> extends AuthTokenSecure<P> {
  readonly plainToken: string;
}
