package org.springframework.security.annotation;

import javax.annotation.security.RolesAllowed;
import javax.annotation.security.PermitAll;

/**
 *
 * @author Luke Taylor
 * @version $Id$
 */
@PermitAll
public class Jsr250BusinessServiceImpl implements BusinessService {

    @RolesAllowed("ROLE_USER")
    public void someUserMethod1() {
    }

    @RolesAllowed("ROLE_USER")
    public void someUserMethod2() {
    }

    @RolesAllowed({"ROLE_USER", "ROLE_ADMIN"})
    public void someUserAndAdminMethod() {
    }

    @RolesAllowed("ROLE_ADMIN")
    public void someAdminMethod() {
    }

    public int someOther(String input) {
        return 0;
    }

    public int someOther(int input) {
        return input;
    }
}
