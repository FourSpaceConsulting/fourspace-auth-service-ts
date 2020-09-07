export enum ActionType {
    Verify,
    PasswordReset,
}
export interface ActionMessage<P> {
    readonly principal: P;
    readonly actionType: ActionType;
    readonly actionToken: string;
}
export interface ActionMessageResponse {
    readonly isSuccess: boolean;
    readonly errorMessage?: string;
}
