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

package org.springframework.security.cas.web;

import junit.framework.TestCase;

import org.springframework.security.MockAuthenticationManager;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;


/**
 * Tests {@link CasAuthenticationFilter}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class CasAuthenticationFilterTests extends TestCase {
    //~ Methods ========================================================================================================

    public void testGetters() {
        CasAuthenticationFilter filter = new CasAuthenticationFilter();
        assertEquals("/j_spring_cas_security_check", filter.getFilterProcessesUrl());
    }

    public void testNormalOperation() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter("ticket", "ST-0-ER94xMJmn6pha35CQRoZ");

        MockAuthenticationManager authMgr = new MockAuthenticationManager(true);

        CasAuthenticationFilter filter = new CasAuthenticationFilter();
        filter.setAuthenticationManager(authMgr);

        Authentication result = filter.attemptAuthentication(request, new MockHttpServletResponse());
        assertTrue(result != null);
    }

    public void testNullServiceTicketHandledGracefully()
        throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();

        MockAuthenticationManager authMgr = new MockAuthenticationManager(false);

        CasAuthenticationFilter filter = new CasAuthenticationFilter();
        filter.setAuthenticationManager(authMgr);

        try {
            filter.attemptAuthentication(request, new MockHttpServletResponse());
            fail("Should have thrown AuthenticationException");
        } catch (AuthenticationException expected) {
            assertTrue(true);
        }
    }
}
