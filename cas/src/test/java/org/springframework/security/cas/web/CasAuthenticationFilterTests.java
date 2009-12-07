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

import static org.junit.Assert.*;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;


/**
 * Tests {@link CasAuthenticationFilter}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class CasAuthenticationFilterTests {
    //~ Methods ========================================================================================================

    @Test
    public void testGetters() {
        CasAuthenticationFilter filter = new CasAuthenticationFilter();
        assertEquals("/j_spring_cas_security_check", filter.getFilterProcessesUrl());
    }

    @Test
    public void testNormalOperation() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter("ticket", "ST-0-ER94xMJmn6pha35CQRoZ");

        CasAuthenticationFilter filter = new CasAuthenticationFilter();
        filter.setAuthenticationManager(new AuthenticationManager() {
            public Authentication authenticate(Authentication a) {
                return a;
            }
        });

        Authentication result = filter.attemptAuthentication(request, new MockHttpServletResponse());
        assertTrue(result != null);
    }

    @Test(expected=AuthenticationException.class)
    public void testNullServiceTicketHandledGracefully() throws Exception {
        CasAuthenticationFilter filter = new CasAuthenticationFilter();
        filter.setAuthenticationManager(new AuthenticationManager() {
            public Authentication authenticate(Authentication a) {
                throw new BadCredentialsException("Rejected");
            }
        });

        filter.attemptAuthentication(new MockHttpServletRequest(), new MockHttpServletResponse());
    }
}
