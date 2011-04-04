package org.springframework.security.access.annotation;

import java.util.ArrayList;
import java.util.List;

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

    public int someOther(String s) {
        return 0;
    }

    public int someOther(int input) {
        return input;
    }

    public List<?> methodReturningAList(List<?> someList) {
        return someList;
    }

    public List<Object> methodReturningAList(String userName, String arg2) {
        return new ArrayList<Object>();
    }

    public Object[] methodReturningAnArray(Object[] someArray) {
        return null;
    }

}
