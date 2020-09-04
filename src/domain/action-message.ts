export interface ActionMessage<P> {
  readonly principal: ReadonlyArray<P>;
  readonly message: string;
  readonly actionLinkTitle: string;
  readonly actionLink: string;
}
