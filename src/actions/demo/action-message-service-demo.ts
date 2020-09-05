import { ActionMessageService } from '../action-message-service';
import { ActionMessage, ActionMessageResponse } from '../../domain/action-message';
import { Principal } from '../../domain/principal';

export class ActionMessageServiceDemo<P extends Principal> implements ActionMessageService<P> {
    private _actionMessages: ActionMessage<P>[] = [];

    /**
     * Getter actionMessages
     * @return {ReadonlyArray<ActionMessage<P>> }
     */
    public get actionMessages(): ReadonlyArray<ActionMessage<P>> {
        return this._actionMessages;
    }

    public sendActionMessage(actionMessage: ActionMessage<P>): Promise<ActionMessageResponse> {
        this._actionMessages.push(actionMessage);
        // tslint:disable-next-line:no-console
        console.log(
            'ActionMessage Type:' +
            actionMessage.actionType +
            ' To [' +
            actionMessage.principal.username +
            '] with token [' +
            actionMessage.actionToken +
            ']'
        );
        return Promise.resolve({ isSuccess: true });
    }
}
