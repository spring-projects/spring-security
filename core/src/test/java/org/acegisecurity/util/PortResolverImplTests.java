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

package org.acegisecurity.util;

import junit.framework.TestCase;
import org.springframework.mock.web.MockHttpServletRequest;



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

    public void testDetectsBuggyIeHttpRequest() throws Exception {
        PortResolverImpl pr = new PortResolverImpl();
        pr.afterPropertiesSet();

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerPort(8443);
        request.setScheme("HTtP"); // proves case insensitive handling
        assertEquals(8080, pr.getServerPort(request));
    }

    public void testDetectsBuggyIeHttpsRequest() throws Exception {
        PortResolverImpl pr = new PortResolverImpl();
        pr.afterPropertiesSet();

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerPort(8080);
        request.setScheme("HTtPs"); // proves case insensitive handling
        assertEquals(8443, pr.getServerPort(request));
    }

    public void testDetectsEmptyPortMapper() throws Exception {
        PortResolverImpl pr = new PortResolverImpl();
        pr.setPortMapper(null);

        try {
            pr.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testGettersSetters() throws Exception {
        PortResolverImpl pr = new PortResolverImpl();
        assertTrue(pr.getPortMapper() != null);
        pr.setPortMapper(new PortMapperImpl());
        assertTrue(pr.getPortMapper() != null);
    }

    public void testNormalOperation() throws Exception {
        PortResolverImpl pr = new PortResolverImpl();
        pr.afterPropertiesSet();

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerPort(1021);
        assertEquals(1021, pr.getServerPort(request));
    }
}
