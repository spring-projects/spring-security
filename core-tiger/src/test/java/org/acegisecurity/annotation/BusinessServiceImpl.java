package org.acegisecurity.annotation;

/**
 *
 * @author Joe Scalise
 */
public class BusinessServiceImpl<E extends Entity> implements BusinessService {

    @Secured({"ROLE_USER"})
    public void someUserMethod1() {
    }

    @Secured({"ROLE_USER"})
    public void someUserMethod2() {
    }

    @Secured({"ROLE_USER", "ROLE_ADMIN"})
    public void someUserAndAdminMethod() {
    }

    @Secured({"ROLE_ADMIN"})
    public void someAdminMethod() {
    }

    public E someUserMethod3(final E entity) {
        return entity;
    }
}
