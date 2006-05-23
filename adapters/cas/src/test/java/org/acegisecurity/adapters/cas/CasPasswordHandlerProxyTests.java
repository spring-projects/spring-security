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

package org.acegisecurity.adapters.cas;

import junit.framework.TestCase;

import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import org.springframework.mock.web.MockHttpServletRequest;

import javax.servlet.http.HttpServletRequest;


/**
 * Tests {@link CasPasswordHandlerProxy}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class CasPasswordHandlerProxyTests extends TestCase {
    //~ Constructors ===================================================================================================

    public CasPasswordHandlerProxyTests() {
        super();
    }

    public CasPasswordHandlerProxyTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(CasPasswordHandlerProxyTests.class);
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testDetectsIfHttpServletRequestNotPassed() {
        CasPasswordHandlerProxy proxy = new MockCasPasswordHandlerProxy(
                "org/acegisecurity/adapters/cas/applicationContext-valid.xml");

        try {
            proxy.authenticate(null, "x", "y");
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("Can only process HttpServletRequest", expected.getMessage());
        }
    }

    public void testDetectsMissingDelegate() {
        CasPasswordHandlerProxy proxy = new MockCasPasswordHandlerProxy(
                "org/acegisecurity/adapters/cas/applicationContext-invalid.xml");

        try {
            proxy.authenticate(new MockHttpServletRequest(), "x", "y");
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("Bean context must contain at least one bean of type CasPasswordHandler", expected.getMessage());
        }
    }

    public void testNormalOperation() {
        CasPasswordHandlerProxy proxy = new MockCasPasswordHandlerProxy(
                "org/acegisecurity/adapters/cas/applicationContext-valid.xml");
        assertTrue(proxy.authenticate(new MockHttpServletRequest(), "marissa", "koala"));
        assertFalse(proxy.authenticate(new MockHttpServletRequest(), "marissa", "WRONG_PASSWORD"));
        assertFalse(proxy.authenticate(new MockHttpServletRequest(), "INVALID_USER_NAME", "WRONG_PASSWORD"));
    }

    //~ Inner Classes ==================================================================================================

    /**
     * Mock object so that application context source can be specified.
     */
    private class MockCasPasswordHandlerProxy extends CasPasswordHandlerProxy {
        private ApplicationContext ctx;

        public MockCasPasswordHandlerProxy(String appContextLocation) {
            ctx = new ClassPathXmlApplicationContext(appContextLocation);
        }

        private MockCasPasswordHandlerProxy() {
            super();
        }

        protected ApplicationContext getContext(HttpServletRequest httpRequest) {
            return ctx;
        }
    }
}
