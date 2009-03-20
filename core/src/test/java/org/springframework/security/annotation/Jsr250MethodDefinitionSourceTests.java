package org.springframework.security.annotation;

import static org.junit.Assert.assertEquals;

import java.util.List;

import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;

import junit.framework.Assert;

import org.junit.Test;
import org.springframework.security.ConfigAttribute;

/**
 * @author Luke Taylor
 * @author Ben Alex
 * @version $Id$
 */
public class Jsr250MethodDefinitionSourceTests {
    Jsr250MethodSecurityMetadataSource mds = new Jsr250MethodSecurityMetadataSource();
    A a = new A();
    UserAllowedClass userAllowed = new UserAllowedClass();
    DenyAllClass denyAll = new DenyAllClass();

    @Test
    public void methodWithRolesAllowedHasCorrectAttribute() throws Exception {
        List<ConfigAttribute> accessAttributes = mds.findAttributes(a.getClass().getMethod("adminMethod"), null);
        assertEquals(1, accessAttributes.size());
        assertEquals("ADMIN", accessAttributes.get(0).toString());
    }

    @Test
    public void permitAllMethodHasPermitAllAttribute() throws Exception {
        List<ConfigAttribute> accessAttributes = mds.findAttributes(a.getClass().getMethod("permitAllMethod"), null);
        assertEquals(1, accessAttributes.size());
        assertEquals("javax.annotation.security.PermitAll", accessAttributes.get(0).toString());
    }

    @Test
    public void noRoleMethodHasDenyAllAttributeWithDenyAllClass() throws Exception {
        List<ConfigAttribute> accessAttributes = mds.findAttributes(denyAll.getClass());
        assertEquals(1, accessAttributes.size());
        assertEquals("javax.annotation.security.DenyAll", accessAttributes.get(0).toString());
    }

    @Test
    public void adminMethodHasAdminAttributeWithDenyAllClass() throws Exception {
        List<ConfigAttribute> accessAttributes = mds.findAttributes(denyAll.getClass().getMethod("adminMethod"), null);
        assertEquals(1, accessAttributes.size());
        assertEquals("ADMIN", accessAttributes.get(0).toString());
    }

    @Test
    public void noRoleMethodHasNoAttributes() throws Exception {
        List<ConfigAttribute> accessAttributes = mds.findAttributes(a.getClass().getMethod("noRoleMethod"), null);
        Assert.assertNull(accessAttributes);
    }

    @Test
    public void classRoleIsAppliedToNoRoleMethod() throws Exception {
        List<ConfigAttribute> accessAttributes = mds.findAttributes(userAllowed.getClass().getMethod("noRoleMethod"), null);
        Assert.assertNull(accessAttributes);
    }

    @Test
    public void methodRoleOverridesClassRole() throws Exception {
        List<ConfigAttribute> accessAttributes = mds.findAttributes(userAllowed.getClass().getMethod("adminMethod"), null);
        assertEquals(1, accessAttributes.size());
        assertEquals("ADMIN", accessAttributes.get(0).toString());
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

    @DenyAll
    public static class DenyAllClass {

        public void noRoleMethod()  {}

        @RolesAllowed("ADMIN")
        public void adminMethod() {}
    }



}
