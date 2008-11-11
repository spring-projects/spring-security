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

package org.springframework.security.intercept;

import junit.framework.TestCase;

import org.springframework.security.MockAccessDecisionManager;
import org.springframework.security.MockAfterInvocationManager;
import org.springframework.security.MockAuthenticationManager;
import org.springframework.security.MockRunAsManager;

import org.springframework.security.intercept.method.MockMethodDefinitionSource;

import org.springframework.security.util.SimpleMethodInvocation;


/**
 * Tests some {@link AbstractSecurityInterceptor} methods. Most of the  testing for this class is found in the
 * <code>MethodSecurityInterceptorTests</code> class.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AbstractSecurityInterceptorTests extends TestCase {
    //~ Constructors ===================================================================================================

    public AbstractSecurityInterceptorTests() {
        super();
    }

    public AbstractSecurityInterceptorTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(AbstractSecurityInterceptorTests.class);
    }

    public void testDetectsIfInvocationPassedIncompatibleSecureObject()
        throws Exception {
        MockSecurityInterceptorWhichOnlySupportsStrings si = new MockSecurityInterceptorWhichOnlySupportsStrings();
        si.setRunAsManager(new MockRunAsManager());
        si.setAuthenticationManager(new MockAuthenticationManager());
        si.setAfterInvocationManager(new MockAfterInvocationManager());
        si.setAccessDecisionManager(new MockAccessDecisionManager());
        si.setObjectDefinitionSource(new MockMethodDefinitionSource(false, true));

        try {
            si.beforeInvocation(new SimpleMethodInvocation());
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().startsWith("Security invocation attempted for object"));
        }
    }

    public void testDetectsViolationOfGetSecureObjectClassMethod()
        throws Exception {
        MockSecurityInterceptorReturnsNull si = new MockSecurityInterceptorReturnsNull();
        si.setRunAsManager(new MockRunAsManager());
        si.setAuthenticationManager(new MockAuthenticationManager());
        si.setAfterInvocationManager(new MockAfterInvocationManager());
        si.setAccessDecisionManager(new MockAccessDecisionManager());
        si.setObjectDefinitionSource(new MockMethodDefinitionSource(false, true));

        try {
            si.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("Subclass must provide a non-null response to getSecureObjectClass()", expected.getMessage());
        }
    }

    //~ Inner Classes ==================================================================================================

    private class MockSecurityInterceptorReturnsNull extends AbstractSecurityInterceptor {
        private ObjectDefinitionSource objectDefinitionSource;

        public Class<? extends Object> getSecureObjectClass() {
            return null;
        }

        public ObjectDefinitionSource obtainObjectDefinitionSource() {
            return objectDefinitionSource;
        }

        public void setObjectDefinitionSource(ObjectDefinitionSource objectDefinitionSource) {
            this.objectDefinitionSource = objectDefinitionSource;
        }
    }

    private class MockSecurityInterceptorWhichOnlySupportsStrings extends AbstractSecurityInterceptor {
        private ObjectDefinitionSource objectDefinitionSource;

        public Class<? extends Object> getSecureObjectClass() {
            return String.class;
        }

        public ObjectDefinitionSource obtainObjectDefinitionSource() {
            return objectDefinitionSource;
        }

        public void setObjectDefinitionSource(ObjectDefinitionSource objectDefinitionSource) {
            this.objectDefinitionSource = objectDefinitionSource;
        }
    }
}
