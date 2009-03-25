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

package org.springframework.security.ui.basicauth;

import junit.framework.TestCase;

import org.springframework.security.DisabledException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;


/**
 * Tests {@link BasicProcessingFilterEntryPoint}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class BasicProcessingFilterEntryPointTests extends TestCase {
    //~ Constructors ===================================================================================================

    public BasicProcessingFilterEntryPointTests() {
        super();
    }

    public BasicProcessingFilterEntryPointTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(BasicProcessingFilterEntryPointTests.class);
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testDetectsMissingRealmName() throws Exception {
        BasicProcessingFilterEntryPoint ep = new BasicProcessingFilterEntryPoint();

        try {
            ep.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("realmName must be specified", expected.getMessage());
        }
    }

    public void testGettersSetters() {
        BasicProcessingFilterEntryPoint ep = new BasicProcessingFilterEntryPoint();
        ep.setRealmName("realm");
        assertEquals("realm", ep.getRealmName());
    }

    public void testNormalOperation() throws Exception {
        BasicProcessingFilterEntryPoint ep = new BasicProcessingFilterEntryPoint();

        ep.setRealmName("hello");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/some_path");

        MockHttpServletResponse response = new MockHttpServletResponse();

        //ep.afterPropertiesSet();

        String msg = "These are the jokes kid";
        ep.commence(request, response, new DisabledException(msg));

        assertEquals(401, response.getStatus());
        assertEquals(msg, response.getErrorMessage());

        assertEquals("Basic realm=\"hello\"", response.getHeader("WWW-Authenticate"));
    }
}
