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
package org.springframework.security.annotation;

import java.lang.reflect.Method;
import java.util.List;

import junit.framework.TestCase;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.ConfigAttribute;
import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.SecurityConfig;
import org.springframework.util.StringUtils;


/**
 * Tests for {@link org.springframework.security.annotation.SecuredMethodDefinitionSource}
 *
 * @author Mark St.Godard
 * @author Joe Scalise
 * @author Ben Alex
 * @version $Id$
 */
public class SecuredMethodDefinitionSourceTests extends TestCase {
    //~ Instance fields ================================================================================================

    private SecuredMethodDefinitionSource mds = new SecuredMethodDefinitionSource();;
    private Log logger = LogFactory.getLog(SecuredMethodDefinitionSourceTests.class);

    //~ Methods ========================================================================================================

    public void testGenericsSuperclassDeclarationsAreIncludedWhenSubclassesOverride() {
        Method method = null;

        try {
            method = DepartmentServiceImpl.class.getMethod("someUserMethod3", new Class[] {Department.class});
        } catch (NoSuchMethodException unexpected) {
            fail("Should be a superMethod called 'someUserMethod3' on class!");
        }

        List<ConfigAttribute> attrs = mds.findAttributes(method, DepartmentServiceImpl.class);

        assertNotNull(attrs);

        if (logger.isDebugEnabled()) {
            logger.debug("attrs: " + StringUtils.collectionToCommaDelimitedString(attrs));
        }

        // expect 1 attribute
        assertTrue("Did not find 1 attribute", attrs.size() == 1);

        // should have 1 SecurityConfig
        for (ConfigAttribute sc : attrs) {
            assertEquals("Found an incorrect role", "ROLE_ADMIN", sc.getAttribute());
        }

        Method superMethod = null;

        try {
            superMethod = DepartmentServiceImpl.class.getMethod("someUserMethod3", new Class[] {Entity.class});
        } catch (NoSuchMethodException unexpected) {
            fail("Should be a superMethod called 'someUserMethod3' on class!");
        }

        List<ConfigAttribute> superAttrs = this.mds.findAttributes(superMethod, DepartmentServiceImpl.class);

        assertNotNull(superAttrs);

        if (logger.isDebugEnabled()) {
            logger.debug("superAttrs: " + StringUtils.collectionToCommaDelimitedString(superAttrs));
        }

        // This part of the test relates to SEC-274
        // expect 1 attribute
        assertEquals("Did not find 1 attribute", 1, superAttrs.size());
        // should have 1 SecurityConfig
        for (ConfigAttribute sc : superAttrs) {
            assertEquals("Found an incorrect role", "ROLE_ADMIN", sc.getAttribute());
        }
    }

    public void testGetAttributesClass() {
        List<ConfigAttribute> attrs = this.mds.findAttributes(BusinessService.class);

        assertNotNull(attrs);

        // expect 1 annotation
        assertEquals(1, attrs.size());

        // should have 1 SecurityConfig
        SecurityConfig sc = ((SecurityConfig) attrs.get(0));

        assertEquals("ROLE_USER", sc.getAttribute());
    }

    public void testGetAttributesMethod() {
        Method method = null;

        try {
            method = BusinessService.class.getMethod("someUserAndAdminMethod", new Class[] {});
        } catch (NoSuchMethodException unexpected) {
            fail("Should be a method called 'someUserAndAdminMethod' on class!");
        }

        List<ConfigAttribute> attrs = this.mds.findAttributes(method, BusinessService.class);

        assertNotNull(attrs);

        // expect 2 attributes
        assertEquals(2, attrs.size());

        boolean user = false;
        boolean admin = false;

        // should have 2 SecurityConfigs
        for (ConfigAttribute sc : attrs) {
            assertTrue(sc instanceof SecurityConfig);

            if (sc.getAttribute().equals("ROLE_USER")) {
                user = true;
            } else if (sc.getAttribute().equals("ROLE_ADMIN")) {
                admin = true;
            }
        }

        // expect to have ROLE_USER and ROLE_ADMIN
        assertTrue(user && admin);
    }

}
