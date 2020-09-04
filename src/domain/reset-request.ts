export interface ResetRequest {
  readonly username: string;
  readonly origin: string;
}

export interface ResetRequestResponse {
  readonly success: boolean;
  readonly username: string;
  readonly origin: string;
  readonly token: string;
}
