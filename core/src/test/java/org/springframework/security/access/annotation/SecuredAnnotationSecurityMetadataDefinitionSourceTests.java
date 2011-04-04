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
package org.springframework.security.access.annotation;

import static org.junit.Assert.*;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.Method;
import java.util.*;

import org.junit.*;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.core.GrantedAuthority;


/**
 * Tests for {@link org.springframework.security.access.annotation.SecuredAnnotationSecurityMetadataSource}
 *
 * @author Mark St.Godard
 * @author Joe Scalise
 * @author Ben Alex
 * @author Luke Taylor
 */
public class SecuredAnnotationSecurityMetadataDefinitionSourceTests {
    //~ Instance fields ================================================================================================

    private SecuredAnnotationSecurityMetadataSource mds = new SecuredAnnotationSecurityMetadataSource();

    //~ Methods ========================================================================================================

    @Test
    public void genericsSuperclassDeclarationsAreIncludedWhenSubclassesOverride() {
        Method method = null;

        try {
            method = DepartmentServiceImpl.class.getMethod("someUserMethod3", new Class[] {Department.class});
        } catch (NoSuchMethodException unexpected) {
            fail("Should be a superMethod called 'someUserMethod3' on class!");
        }

        Collection<ConfigAttribute> attrs = mds.findAttributes(method, DepartmentServiceImpl.class);

        assertNotNull(attrs);

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

        Collection<ConfigAttribute> superAttrs = this.mds.findAttributes(superMethod, DepartmentServiceImpl.class);

        assertNotNull(superAttrs);

        // This part of the test relates to SEC-274
        // expect 1 attribute
        assertEquals("Did not find 1 attribute", 1, superAttrs.size());
        // should have 1 SecurityConfig
        for (ConfigAttribute sc : superAttrs) {
            assertEquals("Found an incorrect role", "ROLE_ADMIN", sc.getAttribute());
        }
    }

    @Test
    public void classLevelAttributesAreFound() {
        Collection<ConfigAttribute> attrs = this.mds.findAttributes(BusinessService.class);

        assertNotNull(attrs);

        // expect 1 annotation
        assertEquals(1, attrs.size());

        // should have 1 SecurityConfig
        SecurityConfig sc = (SecurityConfig) attrs.toArray()[0];

        assertEquals("ROLE_USER", sc.getAttribute());
    }

    @Test
    public void methodLevelAttributesAreFound() {
        Method method = null;

        try {
            method = BusinessService.class.getMethod("someUserAndAdminMethod", new Class[] {});
        } catch (NoSuchMethodException unexpected) {
            fail("Should be a method called 'someUserAndAdminMethod' on class!");
        }

        Collection<ConfigAttribute> attrs = this.mds.findAttributes(method, BusinessService.class);

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

    @Test
    public void customAnnotationAttributesAreFound() throws Exception {
        SecuredAnnotationSecurityMetadataSource mds =
                new SecuredAnnotationSecurityMetadataSource(new CustomSecurityAnnotationMetadataExtractor());
        Collection<ConfigAttribute> attrs = mds.findAttributes(CustomAnnotatedService.class);
        assertEquals(1, attrs.size());
        assertEquals(SecurityEnum.ADMIN, attrs.toArray()[0]);
    }
}

class Department extends Entity {
    public Department(String name) {
        super(name);
    }
}

interface DepartmentService extends BusinessService {

    @Secured({"ROLE_USER"})
    Department someUserMethod3(Department dept);
}

class DepartmentServiceImpl extends BusinessServiceImpl<Department> implements DepartmentService {

    @Secured({"ROLE_ADMIN"})
    public Department someUserMethod3(final Department dept) {
        return super.someUserMethod3(dept);
    }
}

// SEC-1491 Related classes. PoC for custom annotation with enum value.

@CustomSecurityAnnotation(SecurityEnum.ADMIN)
interface CustomAnnotatedService {
}

class CustomAnnotatedServiceImpl implements CustomAnnotatedService {
}

enum SecurityEnum implements ConfigAttribute, GrantedAuthority {
    ADMIN,
    USER;

    public String getAttribute() {
        return toString();
    }

    public String getAuthority() {
        return toString();
    }
}

@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@interface CustomSecurityAnnotation {
    SecurityEnum[] value();
}

class CustomSecurityAnnotationMetadataExtractor implements AnnotationMetadataExtractor<CustomSecurityAnnotation> {

    public Collection<? extends ConfigAttribute> extractAttributes(CustomSecurityAnnotation securityAnnotation) {
        SecurityEnum[] values = securityAnnotation.value();

        return EnumSet.copyOf(Arrays.asList(values));
    }
}
