/**
 * Data access object for Principal objects
 */
export interface PrincipalDao<P> {
    /**
     * get the principal given the username
     * @param username unique username
     */
    getPrincipal(username: string): Promise<P>;

    /**
     * Save the principal
     * @param principal principal
     */
    savePrincipal(principal: P): Promise<P>;
}
