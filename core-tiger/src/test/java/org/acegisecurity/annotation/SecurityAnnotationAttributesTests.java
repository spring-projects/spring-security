/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.acegisecurity.annotation;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Collection;

import junit.framework.TestCase;

import org.acegisecurity.SecurityConfig;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.metadata.Attributes;


/**
 * Tests for {@link org.acegisecurity.annotation.SecurityAnnotationAttributes}
 *
 * @author Mark St.Godard
 * @author Joe Scalise
 * @version $Id$
 */
public class SecurityAnnotationAttributesTests extends TestCase {
    //~ Instance fields ================================================================================================

    private Attributes attributes;
    private Log logger = LogFactory.getLog(SecurityAnnotationAttributesTests.class);

    //~ Methods ========================================================================================================

    protected void setUp() throws Exception {
        // create the Annotations impl
        this.attributes = new SecurityAnnotationAttributes();
    }

    public void testGetAttributesClass() {
        Collection attrs = this.attributes.getAttributes(BusinessService.class);

        assertNotNull(attrs);

        // expect 1 annotation
        assertTrue(attrs.size() == 1);

        // should have 1 SecurityConfig 
        SecurityConfig sc = (SecurityConfig) attrs.iterator().next();

        assertTrue(sc.getAttribute().equals("ROLE_USER"));
    }

    public void testGetAttributesClassClass() {
        try {
            this.attributes.getAttributes(BusinessService.class, null);
            fail("Unsupported method should have thrown an exception!");
        } catch (UnsupportedOperationException expected) {}
    }

    public void testGetAttributesField() {
        try {
            Field field = null;
            this.attributes.getAttributes(field);
            fail("Unsupported method should have thrown an exception!");
        } catch (UnsupportedOperationException expected) {}
    }

    public void testGetAttributesFieldClass() {
        try {
            Field field = null;
            this.attributes.getAttributes(field, null);
            fail("Unsupported method should have thrown an exception!");
        } catch (UnsupportedOperationException expected) {}
    }

    public void testGetAttributesMethod() {
        Method method = null;

        try {
            method = BusinessService.class.getMethod("someUserAndAdminMethod", new Class[] {});
        } catch (NoSuchMethodException unexpected) {
            fail("Should be a method called 'someUserAndAdminMethod' on class!");
        }

        Collection attrs = this.attributes.getAttributes(method);

        assertNotNull(attrs);

        // expect 2 attributes
        assertTrue(attrs.size() == 2);

        boolean user = false;
        boolean admin = false;

        // should have 2 SecurityConfigs 
        for (Object obj : attrs) {
            assertTrue(obj instanceof SecurityConfig);

            SecurityConfig sc = (SecurityConfig) obj;

            if (sc.getAttribute().equals("ROLE_USER")) {
                user = true;
            } else if (sc.getAttribute().equals("ROLE_ADMIN")) {
                admin = true;
            }
        }

        // expect to have ROLE_USER and ROLE_ADMIN
        assertTrue(user && admin);
    }

    public void testGetAttributesMethodClass() {
        Method method = null;

        try {
            method = BusinessService.class.getMethod("someUserAndAdminMethod", new Class[] {});
        } catch (NoSuchMethodException unexpected) {
            fail("Should be a method called 'someUserAndAdminMethod' on class!");
        }

        try {
            this.attributes.getAttributes(method, null);
            fail("Unsupported method should have thrown an exception!");
        } catch (UnsupportedOperationException expected) {}
    }
    
    public void testGenericsSuperclassDeclarationsAreIncludedWhenSubclassesOverride() {

        Method method = null;
        try {
            method = DepartmentServiceImpl.class.getMethod("someUserMethod3", new Class[]{Department.class});
        } catch (NoSuchMethodException unexpected) {
            fail("Should be a superMethod called 'someUserMethod3' on class!");
        }
        Collection attrs = this.attributes.getAttributes(method);

        if (logger.isDebugEnabled()) {
            logger.debug("attrs: ");
            logger.debug(attrs);
        }
        assertNotNull(attrs);

        // expect 1 attribute
        assertTrue("Did not find 1 attribute", attrs.size() == 1);

        // should have 1 SecurityConfig
        for (Object obj : attrs) {
            assertTrue(obj instanceof SecurityConfig);
            SecurityConfig sc = (SecurityConfig) obj;
            assertEquals("Found an incorrect role", "ROLE_ADMIN", sc.getAttribute());
        }

        Method superMethod = null;
        try {
            superMethod = DepartmentServiceImpl.class.getMethod("someUserMethod3", new Class[]{Entity.class});
        } catch (NoSuchMethodException unexpected) {
            fail("Should be a superMethod called 'someUserMethod3' on class!");
        }
        System.out.println(superMethod);
        Collection superAttrs = this.attributes.getAttributes(superMethod);

        if (logger.isDebugEnabled()) {
            logger.debug("superAttrs: ");
            logger.debug(superAttrs);
        }
        assertNotNull(superAttrs);
        
        // TODO: Resolve bridge method bug as reported in SEC-274
        /*
        // expect 1 attribute
        assertTrue("Did not find 1 attribute", superAttrs.size() == 1);

        // should have 1 SecurityConfig
        for (Object obj : superAttrs) {
            assertTrue(obj instanceof SecurityConfig);
            SecurityConfig sc = (SecurityConfig) obj;
            assertEquals("Found an incorrect role", "ROLE_ADMIN", sc.getAttribute());
        }
        */
    }   
}
