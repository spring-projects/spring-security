/*
 * Copyright 2002-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.access.annotation;

import static org.fest.assertions.Assertions.assertThat;
import static org.junit.Assert.assertEquals;

import java.util.Collection;

import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;

import org.junit.Assert;
import org.junit.Test;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.intercept.method.MockMethodInvocation;

/**
 * @author Luke Taylor
 * @author Ben Alex
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

    // JSR-250 Spec Tests

    /**
     *  Class-level annotations only affect the class they annotate and their members, that
     *  is, its methods and fields. They never affect a member declared by a superclass,
     * even if it is not hidden or overridden by the class in question.
     * @throws Exception
     */
    @Test
    public void classLevelAnnotationsOnlyAffectTheClassTheyAnnotateAndTheirMembers() throws Exception {
        Child target = new Child();
        MockMethodInvocation mi = new MockMethodInvocation(target, target.getClass(), "notOverriden");

        Collection<ConfigAttribute> accessAttributes = mds.getAttributes(mi);
        assertThat(accessAttributes).isNull();
    }

    @Test
    public void classLevelAnnotationsOnlyAffectTheClassTheyAnnotateAndTheirMembersOverriden() throws Exception {
        Child target = new Child();
        MockMethodInvocation mi = new MockMethodInvocation(target, target.getClass(), "overriden");

        Collection<ConfigAttribute> accessAttributes = mds.getAttributes(mi);
        assertEquals(1, accessAttributes.size());
        assertEquals("DERIVED", accessAttributes.toArray()[0].toString());
    }

    @Test
    public void classLevelAnnotationsImpactMemberLevel() throws Exception {
        Child target = new Child();
        MockMethodInvocation mi = new MockMethodInvocation(target, target.getClass(), "defaults");

        Collection<ConfigAttribute> accessAttributes = mds.getAttributes(mi);
        assertEquals(1, accessAttributes.size());
        assertEquals("DERIVED", accessAttributes.toArray()[0].toString());
    }

    @Test
    public void classLevelAnnotationsIgnoredByExplicitMemberAnnotation() throws Exception {
        Child target = new Child();
        MockMethodInvocation mi = new MockMethodInvocation(target, target.getClass(), "explicitMethod");

        Collection<ConfigAttribute> accessAttributes = mds.getAttributes(mi);
        assertEquals(1, accessAttributes.size());
        assertEquals("EXPLICIT", accessAttributes.toArray()[0].toString());
    }

    /**
     * The interfaces implemented by a class never contribute annotations to the class
     * itself or any of its members.
     * @throws Exception
     */
    @Test
    public void interfacesNeverContributeAnnotationsMethodLevel() throws Exception {
        Parent target = new Parent();
        MockMethodInvocation mi = new MockMethodInvocation(target, target.getClass(), "interfaceMethod");

        Collection<ConfigAttribute> accessAttributes = mds.getAttributes(mi);
        assertThat(accessAttributes).isEmpty();
    }

    @Test
    public void interfacesNeverContributeAnnotationsClassLevel() throws Exception {
        Parent target = new Parent();
        MockMethodInvocation mi = new MockMethodInvocation(target, target.getClass(), "notOverriden");

        Collection<ConfigAttribute> accessAttributes = mds.getAttributes(mi);
        assertThat(accessAttributes).isEmpty();
    }

    @Test
    public void annotationsOnOverriddenMemberIgnored() throws Exception {
        Child target = new Child();
        MockMethodInvocation mi = new MockMethodInvocation(target, target.getClass(), "overridenIgnored");

        Collection<ConfigAttribute> accessAttributes = mds.getAttributes(mi);
        assertEquals(1, accessAttributes.size());
        assertEquals("DERIVED", accessAttributes.toArray()[0].toString());
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

    // JSR-250 Spec

    @RolesAllowed("IPARENT")
    interface IParent {
        @RolesAllowed("INTERFACEMETHOD")
        void interfaceMethod();
    }

    static class Parent implements IParent {
        public void interfaceMethod() {}
        public void notOverriden() {}
        public void overriden() {}
        @RolesAllowed("OVERRIDENIGNORED")
        public void overridenIgnored() {}
    }

    @RolesAllowed("DERIVED")
    class Child extends Parent {
        public void overriden() {}
        public void overridenIgnored() {}
        public void defaults() {}
        @RolesAllowed("EXPLICIT")
        public void explicitMethod() {}
    }
}
