import { ActionMessage, ActionMessageResponse } from '../domain/action-message';

/**
 * Service for sending principal action messages
 * These would typically be emails to users containing links for registration/password resets.
 */
export interface ActionMessageService<P> {
    /**
     * Send the message
     * @param actionMessage message
     */
    sendActionMessage(actionMessage: ActionMessage<P>): Promise<ActionMessageResponse>;
}
