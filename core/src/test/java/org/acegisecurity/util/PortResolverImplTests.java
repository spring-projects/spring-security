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

package net.sf.acegisecurity.util;

import junit.framework.TestCase;

import net.sf.acegisecurity.MockHttpServletRequest;


/**
 * Tests {@link PortResolverImpl}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class PortResolverImplTests extends TestCase {
    //~ Constructors ===========================================================

    public PortResolverImplTests() {
        super();
    }

    public PortResolverImplTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(PortResolverImplTests.class);
    }

    public void testGettersSetters() throws Exception {
        PortResolverImpl pr = new PortResolverImpl();
        assertEquals(0, pr.getAlwaysHttpPort());
        assertEquals(0, pr.getAlwaysHttpsPort());

        pr.setAlwaysHttpPort(80);
        pr.setAlwaysHttpsPort(443);
        assertEquals(80, pr.getAlwaysHttpPort());
        assertEquals(443, pr.getAlwaysHttpsPort());
    }

    public void testNormalOperation() throws Exception {
        PortResolverImpl pr = new PortResolverImpl();
        pr.afterPropertiesSet();

        MockHttpServletRequest request = new MockHttpServletRequest("X");
        request.setScheme("http");
        request.setServerPort(1021);
        assertEquals(1021, pr.getServerPort(request));
    }

    public void testOverridesHttp() throws Exception {
        PortResolverImpl pr = new PortResolverImpl();
        pr.setAlwaysHttpPort(495);
        pr.afterPropertiesSet();

        MockHttpServletRequest request = new MockHttpServletRequest("X");
        request.setServerPort(7676);
        request.setScheme("HTtP"); // proves case insensitive handling
        assertEquals(495, pr.getServerPort(request));

        request.setScheme("https");
        assertEquals(7676, pr.getServerPort(request));
    }

    public void testOverridesHttps() throws Exception {
        PortResolverImpl pr = new PortResolverImpl();
        pr.setAlwaysHttpsPort(987);
        pr.afterPropertiesSet();

        MockHttpServletRequest request = new MockHttpServletRequest("X");
        request.setServerPort(6949);
        request.setScheme("HTtPs"); // proves case insensitive handling
        assertEquals(987, pr.getServerPort(request));

        request.setScheme("http");
        assertEquals(6949, pr.getServerPort(request));
    }

    public void testRejectsOutOfRangeHttp() throws Exception {
        PortResolverImpl pr = new PortResolverImpl();
        pr.setAlwaysHttpPort(9999999);

        try {
            pr.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("alwaysHttpPort must be between 1 and 65535",
                expected.getMessage());
        }

        pr.setAlwaysHttpPort(-49);

        try {
            pr.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("alwaysHttpPort must be between 1 and 65535",
                expected.getMessage());
        }
    }

    public void testRejectsOutOfRangeHttps() throws Exception {
        PortResolverImpl pr = new PortResolverImpl();
        pr.setAlwaysHttpsPort(9999999);

        try {
            pr.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("alwaysHttpsPort must be between 1 and 65535",
                expected.getMessage());
        }

        pr.setAlwaysHttpsPort(-49);

        try {
            pr.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("alwaysHttpsPort must be between 1 and 65535",
                expected.getMessage());
        }
    }
}
