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

package org.springframework.security.intercept.web;

import junit.framework.TestCase;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;


/**
 * Tests {@link AbstractFilterInvocationDefinitionSource}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AbstractFilterInvocationDefinitionSourceTests extends TestCase {
    //~ Constructors ===================================================================================================

    public AbstractFilterInvocationDefinitionSourceTests() {
        super();
    }

    public AbstractFilterInvocationDefinitionSourceTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(AbstractFilterInvocationDefinitionSourceTests.class);
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testDoesNotSupportAnotherObject() {
        MockFilterInvocationDefinitionSource mfis = new MockFilterInvocationDefinitionSource(false, true);
        assertFalse(mfis.supports(String.class));
    }

    public void testGetAttributesForANonFilterInvocation() {
        MockFilterInvocationDefinitionSource mfis = new MockFilterInvocationDefinitionSource(false, true);

        try {
            mfis.getAttributes(new String());
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testGetAttributesForANullObject() {
        MockFilterInvocationDefinitionSource mfis = new MockFilterInvocationDefinitionSource(false, true);

        try {
            mfis.getAttributes(null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testGetAttributesForFilterInvocationSuccess() {
        MockFilterInvocationDefinitionSource mfis = new MockFilterInvocationDefinitionSource(false, true);

        try {
            mfis.getAttributes(new FilterInvocation(new MockHttpServletRequest(null, null),
                    new MockHttpServletResponse(), new MockFilterChain()));
            fail("Should have thrown UnsupportedOperationException");
        } catch (UnsupportedOperationException expected) {
            assertTrue(true);
        }
    }

    public void testSupportsFilterInvocation() {
        MockFilterInvocationDefinitionSource mfis = new MockFilterInvocationDefinitionSource(false, true);
        assertTrue(mfis.supports(FilterInvocation.class));
    }

    //~ Inner Classes ==================================================================================================

    private class MockFilterChain implements FilterChain {
        public void doFilter(ServletRequest arg0, ServletResponse arg1)
            throws IOException, ServletException {
            throw new UnsupportedOperationException("mock method not implemented");
        }
    }
}
