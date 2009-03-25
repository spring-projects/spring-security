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

package org.springframework.security.afterinvocation;

import java.util.List;
import java.util.Vector;

import junit.framework.TestCase;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.AccessDeniedException;
import org.springframework.security.Authentication;
import org.springframework.security.ConfigAttribute;
import org.springframework.security.SecurityConfig;
import org.springframework.security.util.SimpleMethodInvocation;


/**
 * Tests {@link AfterInvocationProviderManager}.
 *
 * @author Ben Alex
 * @version $Id$
 */
@SuppressWarnings("unchecked")
public class AfterInvocationProviderManagerTests extends TestCase {

    //~ Methods ========================================================================================================

    public void testCorrectOperation() throws Exception {
        AfterInvocationProviderManager manager = new AfterInvocationProviderManager();
        List list = new Vector();
        list.add(new MockAfterInvocationProvider("swap1", MethodInvocation.class, new SecurityConfig("GIVE_ME_SWAP1")));
        list.add(new MockAfterInvocationProvider("swap2", MethodInvocation.class, new SecurityConfig("GIVE_ME_SWAP2")));
        list.add(new MockAfterInvocationProvider("swap3", MethodInvocation.class, new SecurityConfig("GIVE_ME_SWAP3")));
        manager.setProviders(list);
        assertEquals(list, manager.getProviders());
        manager.afterPropertiesSet();

        List<ConfigAttribute> attr1 = SecurityConfig.createList(new String[] {"GIVE_ME_SWAP1"});
        List<ConfigAttribute> attr2 = SecurityConfig.createList(new String[] {"GIVE_ME_SWAP2"});
        List<ConfigAttribute> attr3 = SecurityConfig.createList(new String[] {"GIVE_ME_SWAP3"});
        List<ConfigAttribute> attr2and3 = SecurityConfig.createList(new String[] {"GIVE_ME_SWAP2","GIVE_ME_SWAP3"});
        List<ConfigAttribute> attr4 = SecurityConfig.createList(new String[] {"NEVER_CAUSES_SWAP"});

        assertEquals("swap1", manager.decide(null, new SimpleMethodInvocation(), attr1, "content-before-swapping"));

        assertEquals("swap2", manager.decide(null, new SimpleMethodInvocation(), attr2, "content-before-swapping"));

        assertEquals("swap3", manager.decide(null, new SimpleMethodInvocation(), attr3, "content-before-swapping"));

        assertEquals("content-before-swapping",
            manager.decide(null, new SimpleMethodInvocation(), attr4, "content-before-swapping"));

        assertEquals("swap3", manager.decide(null, new SimpleMethodInvocation(), attr2and3, "content-before-swapping"));
    }

    public void testRejectsEmptyProvidersList() {
        AfterInvocationProviderManager manager = new AfterInvocationProviderManager();
        List list = new Vector();

        try {
            manager.setProviders(list);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testRejectsNonAfterInvocationProviders() {
        AfterInvocationProviderManager manager = new AfterInvocationProviderManager();
        List list = new Vector();
        list.add(new MockAfterInvocationProvider("swap1", MethodInvocation.class, new SecurityConfig("GIVE_ME_SWAP1")));
        list.add(new Integer(45));
        list.add(new MockAfterInvocationProvider("swap3", MethodInvocation.class, new SecurityConfig("GIVE_ME_SWAP3")));

        try {
            manager.setProviders(list);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testRejectsNullProvidersList() throws Exception {
        AfterInvocationProviderManager manager = new AfterInvocationProviderManager();

        try {
            manager.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testSupportsConfigAttributeIteration()
        throws Exception {
        AfterInvocationProviderManager manager = new AfterInvocationProviderManager();
        List list = new Vector();
        list.add(new MockAfterInvocationProvider("swap1", MethodInvocation.class, new SecurityConfig("GIVE_ME_SWAP1")));
        list.add(new MockAfterInvocationProvider("swap2", MethodInvocation.class, new SecurityConfig("GIVE_ME_SWAP2")));
        list.add(new MockAfterInvocationProvider("swap3", MethodInvocation.class, new SecurityConfig("GIVE_ME_SWAP3")));
        manager.setProviders(list);
        manager.afterPropertiesSet();

        assertFalse(manager.supports(new SecurityConfig("UNKNOWN_ATTRIB")));
        assertTrue(manager.supports(new SecurityConfig("GIVE_ME_SWAP2")));
    }

    public void testSupportsSecureObjectIteration() throws Exception {
        AfterInvocationProviderManager manager = new AfterInvocationProviderManager();
        List list = new Vector();
        list.add(new MockAfterInvocationProvider("swap1", MethodInvocation.class, new SecurityConfig("GIVE_ME_SWAP1")));
        list.add(new MockAfterInvocationProvider("swap2", MethodInvocation.class, new SecurityConfig("GIVE_ME_SWAP2")));
        list.add(new MockAfterInvocationProvider("swap3", MethodInvocation.class, new SecurityConfig("GIVE_ME_SWAP3")));
        manager.setProviders(list);
        manager.afterPropertiesSet();

//        assertFalse(manager.supports(FilterInvocation.class));
        assertTrue(manager.supports(MethodInvocation.class));
    }

    //~ Inner Classes ==================================================================================================

    /**
     * Always returns the constructor-defined <code>forceReturnObject</code>, provided the same configuration
     * attribute was provided. Also stores the secure object it supports.
     */
    private class MockAfterInvocationProvider implements AfterInvocationProvider {
        private Class secureObject;
        private ConfigAttribute configAttribute;
        private Object forceReturnObject;

        public MockAfterInvocationProvider(Object forceReturnObject, Class secureObject, ConfigAttribute configAttribute) {
            this.forceReturnObject = forceReturnObject;
            this.secureObject = secureObject;
            this.configAttribute = configAttribute;
        }

        public Object decide(Authentication authentication, Object object, List<ConfigAttribute> config,
            Object returnedObject) throws AccessDeniedException {
            if (config.contains(configAttribute)) {
                return forceReturnObject;
            }

            return returnedObject;
        }

        public boolean supports(Class<?> clazz) {
            return secureObject.isAssignableFrom(clazz);
        }

        public boolean supports(ConfigAttribute attribute) {
            return attribute.equals(configAttribute);
        }
    }
}
