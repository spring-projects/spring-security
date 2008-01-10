package org.springframework.security.annotation;

import org.springframework.security.SecurityConfig;

import org.junit.Test;
import static org.junit.Assert.*;

import java.util.List;
import java.util.ArrayList;

import javax.annotation.security.RolesAllowed;
import javax.annotation.security.PermitAll;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class Jsr250SecurityAnnotationAttributesTests {
    Jsr250SecurityAnnotationAttributes attributes = new Jsr250SecurityAnnotationAttributes();
    A a = new A();
    B b = new B();

    @Test
    public void methodWithRolesAllowedHasCorrectAttribute() throws Exception {
//        Method[] methods = a.getClass().getMethods();

        List<SecurityConfig> accessAttributes =
                new ArrayList<SecurityConfig>(attributes.getAttributes(a.getClass().getMethod("adminMethod")));
        assertEquals(1, accessAttributes.size());
        assertEquals("ADMIN", accessAttributes.get(0).getAttribute());
    }

    @Test
    public void permitAllMethodHasNoAttributes() throws Exception {
        List<SecurityConfig> accessAttributes =
                new ArrayList<SecurityConfig>(attributes.getAttributes(a.getClass().getMethod("permitAllMethod")));
        assertEquals(0, accessAttributes.size());
    }

    @Test
    public void noRoleMethodHasNoAttributes() throws Exception {
        List<SecurityConfig> accessAttributes =
                new ArrayList<SecurityConfig>(attributes.getAttributes(a.getClass().getMethod("noRoleMethod")));
        assertEquals(0, accessAttributes.size());
    }
    
    @Test
    public void classRoleIsAppliedNoRoleMethod() throws Exception {
        List<SecurityConfig> accessAttributes =
                new ArrayList<SecurityConfig>(attributes.getAttributes(b.getClass().getMethod("noRoleMethod")));
        assertEquals(1, accessAttributes.size());
        assertEquals("USER", accessAttributes.get(0).getAttribute());
    }

    @Test
    public void methodRoleOverridesClassRole() throws Exception {
        List<SecurityConfig> accessAttributes =
                new ArrayList<SecurityConfig>(attributes.getAttributes(b.getClass().getMethod("adminMethod")));
        assertEquals(1, accessAttributes.size());
        assertEquals("ADMIN", accessAttributes.get(0).getAttribute());
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
    public static class B {
        public void noRoleMethod() {}

        @RolesAllowed("ADMIN")
        public void adminMethod() {}        
    }

}
