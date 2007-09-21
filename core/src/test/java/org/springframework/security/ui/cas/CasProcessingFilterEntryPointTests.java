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

package org.springframework.security.ui.cas;

import junit.framework.TestCase;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.net.URLEncoder;


/**
 * Tests {@link CasProcessingFilterEntryPoint}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class CasProcessingFilterEntryPointTests extends TestCase {
    //~ Constructors ===================================================================================================

    public CasProcessingFilterEntryPointTests() {
        super();
    }

    public CasProcessingFilterEntryPointTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(CasProcessingFilterEntryPointTests.class);
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testDetectsMissingLoginFormUrl() throws Exception {
        CasProcessingFilterEntryPoint ep = new CasProcessingFilterEntryPoint();
        ep.setServiceProperties(new ServiceProperties());

        try {
            ep.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("loginUrl must be specified", expected.getMessage());
        }
    }

    public void testDetectsMissingServiceProperties() throws Exception {
        CasProcessingFilterEntryPoint ep = new CasProcessingFilterEntryPoint();
        ep.setLoginUrl("https://cas/login");

        try {
            ep.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("serviceProperties must be specified", expected.getMessage());
        }
    }

    public void testGettersSetters() {
        CasProcessingFilterEntryPoint ep = new CasProcessingFilterEntryPoint();
        ep.setLoginUrl("https://cas/login");
        assertEquals("https://cas/login", ep.getLoginUrl());

        ep.setServiceProperties(new ServiceProperties());
        assertTrue(ep.getServiceProperties() != null);
    }

    public void testNormalOperationWithRenewFalse() throws Exception {
        ServiceProperties sp = new ServiceProperties();
        sp.setSendRenew(false);
        sp.setService("https://mycompany.com/bigWebApp/j_acegi_cas_security_check");

        CasProcessingFilterEntryPoint ep = new CasProcessingFilterEntryPoint();
        ep.setLoginUrl("https://cas/login");
        ep.setServiceProperties(sp);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/some_path");

        MockHttpServletResponse response = new MockHttpServletResponse();

        ep.afterPropertiesSet();
        ep.commence(request, response, null);

        assertEquals("https://cas/login?service="
            + URLEncoder.encode("https://mycompany.com/bigWebApp/j_acegi_cas_security_check", "UTF-8"),
            response.getRedirectedUrl());
    }

    public void testNormalOperationWithRenewTrue() throws Exception {
        ServiceProperties sp = new ServiceProperties();
        sp.setSendRenew(true);
        sp.setService("https://mycompany.com/bigWebApp/j_acegi_cas_security_check");

        CasProcessingFilterEntryPoint ep = new CasProcessingFilterEntryPoint();
        ep.setLoginUrl("https://cas/login");
        ep.setServiceProperties(sp);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/some_path");

        MockHttpServletResponse response = new MockHttpServletResponse();

        ep.afterPropertiesSet();
        ep.commence(request, response, null);
        assertEquals("https://cas/login?service="
            + URLEncoder.encode("https://mycompany.com/bigWebApp/j_acegi_cas_security_check", "UTF-8") + "&renew=true",
            response.getRedirectedUrl());
    }
}
