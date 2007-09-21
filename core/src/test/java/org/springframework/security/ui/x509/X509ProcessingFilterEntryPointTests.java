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

package org.springframework.security.ui.x509;

import junit.framework.TestCase;

import org.springframework.security.BadCredentialsException;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.http.HttpServletResponse;


/**
 * Tests {@link X509ProcessingFilterEntryPoint}.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class X509ProcessingFilterEntryPointTests extends TestCase {
    //~ Constructors ===================================================================================================

    public X509ProcessingFilterEntryPointTests() {
        super();
    }

    public X509ProcessingFilterEntryPointTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testNormalOperation() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        X509ProcessingFilterEntryPoint entryPoint = new X509ProcessingFilterEntryPoint();

        entryPoint.commence(request, response, new BadCredentialsException("As thrown by security enforcement filter"));
        assertEquals(HttpServletResponse.SC_FORBIDDEN, response.getStatus());
    }
}
