/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.adapters.cas;

import junit.framework.TestCase;

import net.sf.acegisecurity.MockAuthenticationManager;

import org.springframework.mock.web.MockHttpServletRequest;


/**
 * Tests {@link CasPasswordHandler}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class CasPasswordHandlerTests extends TestCase {
    //~ Constructors ===========================================================

    public CasPasswordHandlerTests() {
        super();
    }

    public CasPasswordHandlerTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(CasPasswordHandlerTests.class);
    }

    public void testDeniesAccessWhenAuthenticationManagerThrowsException()
        throws Exception {
        CasPasswordHandler handler = new CasPasswordHandler();
        handler.setAuthenticationManager(new MockAuthenticationManager(false));
        handler.afterPropertiesSet();

        assertFalse(handler.authenticate(new MockHttpServletRequest(),
                "username", "password"));
    }

    public void testDetectsEmptyAuthenticationManager()
        throws Exception {
        CasPasswordHandler handler = new CasPasswordHandler();

        try {
            handler.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("An AuthenticationManager is required",
                expected.getMessage());
        }
    }

    public void testGettersSetters() {
        CasPasswordHandler handler = new CasPasswordHandler();
        handler.setAuthenticationManager(new MockAuthenticationManager(false));
        assertTrue(handler.getAuthenticationManager() != null);
    }

    public void testGracefullyHandlesEmptyUsernamesAndPassword()
        throws Exception {
        CasPasswordHandler handler = new CasPasswordHandler();
        handler.setAuthenticationManager(new MockAuthenticationManager(true));
        handler.afterPropertiesSet();

        // If empty or null username we return false
        assertFalse(handler.authenticate(new MockHttpServletRequest(), "",
                "password"));
        assertFalse(handler.authenticate(new MockHttpServletRequest(), null,
                "password"));

        // We authenticate with null passwords (they might not have one)
        assertTrue(handler.authenticate(new MockHttpServletRequest(), "user",
                null));
        assertTrue(handler.authenticate(new MockHttpServletRequest(), "user", ""));
    }

    public void testNormalOperation() throws Exception {
        CasPasswordHandler handler = new CasPasswordHandler();
        handler.setAuthenticationManager(new MockAuthenticationManager(true));
        handler.afterPropertiesSet();

        assertTrue(handler.authenticate(new MockHttpServletRequest(),
                "username", "password"));
    }
}
