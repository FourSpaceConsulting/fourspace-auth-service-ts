/**
 * Mapper for new users from an API request.
 *
 * Validates the new user passed in to the create user request
 *
 * Creates the new user
 *
 */
export interface RequestUserMapper<P, PDTO> {
    validateNewUser(obj: any): Promise<boolean>;
    createNewUser(obj: any): P;
    mapToDto(p: P): PDTO;
}
