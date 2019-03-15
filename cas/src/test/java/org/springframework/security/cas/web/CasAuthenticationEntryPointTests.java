/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.cas.web;

import junit.framework.TestCase;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;

import java.net.URLEncoder;


/**
 * Tests {@link CasAuthenticationEntryPoint}.
 *
 * @author Ben Alex
 */
public class CasAuthenticationEntryPointTests extends TestCase {
    //~ Methods ========================================================================================================

    public void testDetectsMissingLoginFormUrl() throws Exception {
        CasAuthenticationEntryPoint ep = new CasAuthenticationEntryPoint();
        ep.setServiceProperties(new ServiceProperties());

        try {
            ep.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("loginUrl must be specified", expected.getMessage());
        }
    }

    public void testDetectsMissingServiceProperties() throws Exception {
        CasAuthenticationEntryPoint ep = new CasAuthenticationEntryPoint();
        ep.setLoginUrl("https://cas/login");

        try {
            ep.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("serviceProperties must be specified", expected.getMessage());
        }
    }

    public void testGettersSetters() {
        CasAuthenticationEntryPoint ep = new CasAuthenticationEntryPoint();
        ep.setLoginUrl("https://cas/login");
        assertEquals("https://cas/login", ep.getLoginUrl());

        ep.setServiceProperties(new ServiceProperties());
        assertTrue(ep.getServiceProperties() != null);
    }

    public void testNormalOperationWithRenewFalse() throws Exception {
        ServiceProperties sp = new ServiceProperties();
        sp.setSendRenew(false);
        sp.setService("https://mycompany.com/bigWebApp/j_spring_cas_security_check");

        CasAuthenticationEntryPoint ep = new CasAuthenticationEntryPoint();
        ep.setLoginUrl("https://cas/login");
        ep.setServiceProperties(sp);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/some_path");

        MockHttpServletResponse response = new MockHttpServletResponse();

        ep.afterPropertiesSet();
        ep.commence(request, response, null);

        assertEquals("https://cas/login?service="
            + URLEncoder.encode("https://mycompany.com/bigWebApp/j_spring_cas_security_check", "UTF-8"),
            response.getRedirectedUrl());
    }

    public void testNormalOperationWithRenewTrue() throws Exception {
        ServiceProperties sp = new ServiceProperties();
        sp.setSendRenew(true);
        sp.setService("https://mycompany.com/bigWebApp/j_spring_cas_security_check");

        CasAuthenticationEntryPoint ep = new CasAuthenticationEntryPoint();
        ep.setLoginUrl("https://cas/login");
        ep.setServiceProperties(sp);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/some_path");

        MockHttpServletResponse response = new MockHttpServletResponse();

        ep.afterPropertiesSet();
        ep.commence(request, response, null);
        assertEquals("https://cas/login?service="
            + URLEncoder.encode("https://mycompany.com/bigWebApp/j_spring_cas_security_check", "UTF-8") + "&renew=true",
            response.getRedirectedUrl());
    }
}
