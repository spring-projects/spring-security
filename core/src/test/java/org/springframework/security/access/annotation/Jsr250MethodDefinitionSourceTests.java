package org.springframework.security.access.annotation;

import static org.junit.Assert.assertEquals;

import java.util.Collection;

import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;

import junit.framework.Assert;

import org.junit.Test;
import org.springframework.security.access.ConfigAttribute;

/**
 * @author Luke Taylor
 * @author Ben Alex
 * @version $Id$
 */
public class Jsr250MethodDefinitionSourceTests {
    Jsr250MethodSecurityMetadataSource mds = new Jsr250MethodSecurityMetadataSource();
    A a = new A();
    UserAllowedClass userAllowed = new UserAllowedClass();

    private ConfigAttribute[] findAttributes(String methodName) throws Exception {
        return mds.findAttributes(a.getClass().getMethod(methodName), null).toArray(new ConfigAttribute[0]);
    }

    @Test
    public void methodWithRolesAllowedHasCorrectAttribute() throws Exception {
        ConfigAttribute[] accessAttributes = findAttributes("adminMethod");
        assertEquals(1, accessAttributes.length);
        assertEquals("ADMIN", accessAttributes[0].toString());
    }

    @Test
    public void permitAllMethodHasPermitAllAttribute() throws Exception {
        ConfigAttribute[] accessAttributes = findAttributes("permitAllMethod");
        assertEquals(1, accessAttributes.length);
        assertEquals("javax.annotation.security.PermitAll", accessAttributes[0].toString());
    }

    @Test
    public void noRoleMethodHasNoAttributes() throws Exception {
        Collection<ConfigAttribute> accessAttributes = mds.findAttributes(a.getClass().getMethod("noRoleMethod"), null);
        Assert.assertNull(accessAttributes);
    }

    @Test
    public void classRoleIsAppliedToNoRoleMethod() throws Exception {
        Collection<ConfigAttribute> accessAttributes = mds.findAttributes(userAllowed.getClass().getMethod("noRoleMethod"), null);
        Assert.assertNull(accessAttributes);
    }

    @Test
    public void methodRoleOverridesClassRole() throws Exception {
        Collection<ConfigAttribute> accessAttributes = mds.findAttributes(userAllowed.getClass().getMethod("adminMethod"), null);
        assertEquals(1, accessAttributes.size());
        assertEquals("ADMIN", accessAttributes.toArray()[0].toString());
    }

//~ Inner Classes ======================================================================================================

    public static class A {

        public void noRoleMethod() {}

        @RolesAllowed("ADMIN")
        public void adminMethod() {}

        @PermitAll
        public void permitAllMethod() {}
    }

    @RolesAllowed("USER")
    public static class UserAllowedClass {
        public void noRoleMethod() {}

        @RolesAllowed("ADMIN")
        public void adminMethod() {}
    }
}
