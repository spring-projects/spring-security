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

package org.springframework.security.ui.webapp;

import junit.framework.TestCase;

import org.springframework.security.Authentication;
import org.springframework.security.MockAuthenticationManager;
import org.springframework.security.ui.WebAuthenticationDetails;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * Tests SiteminderAuthenticationProcessingFilter.
 *
 * @author Ben Alex
 * @author <a href="mailto:scott@mccrory.us">Scott McCrory</a>
 * @version CVS $Id$
 */
public class SiteminderAuthenticationProcessingFilterTests extends TestCase {
    //~ Constructors ===================================================================================================

    /**
     * Basic constructor.
     */
    public SiteminderAuthenticationProcessingFilterTests() {
        super();
    }

    /**
     * Argument constructor.
     *
     * @param arg0
     */
    public SiteminderAuthenticationProcessingFilterTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    /**
     * Runs the tests as a command-line program.
     *
     * @param args
     */
    public static void main(String[] args) {
        junit.textui.TestRunner.run(SiteminderAuthenticationProcessingFilterTests.class);
    }

    /**
     *
     * @see junit.framework.TestCase#setUp()
     */
    public final void setUp() throws Exception {
        super.setUp();
    }

    /**
     * Tests the class' getters.
     */
    public void testAccessors() {
        SiteminderAuthenticationProcessingFilter filter = new SiteminderAuthenticationProcessingFilter();

        filter.setAlwaysUseDefaultTargetUrl(true);
        assertTrue(filter.isAlwaysUseDefaultTargetUrl());

        filter.setAuthenticationFailureUrl("foo");
        assertEquals("foo", filter.getAuthenticationFailureUrl());

        filter.setContinueChainBeforeSuccessfulAuthentication(true);
        assertTrue(filter.isContinueChainBeforeSuccessfulAuthentication());

        filter.setDefaultTargetUrl("/bar");
        assertEquals("/bar", filter.getDefaultTargetUrl());

        filter.setFilterProcessesUrl("foobar");
        assertEquals("foobar", filter.getFilterProcessesUrl());

        filter.setFormUsernameParameterKey("usernameParamKey");
        assertEquals("usernameParamKey", filter.getFormUsernameParameterKey());

        filter.setSiteminderUsernameHeaderKey("usernameHeaderKey");
        assertEquals("usernameHeaderKey", filter.getSiteminderUsernameHeaderKey());
    }

    /**
     * Tests normal form processing.
     *
     * @throws Exception
     */
    public void testFormNormalOperation() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter(SiteminderAuthenticationProcessingFilter.ACEGI_SECURITY_FORM_USERNAME_KEY, "marissa");
        request.addParameter(SiteminderAuthenticationProcessingFilter.ACEGI_SECURITY_FORM_PASSWORD_KEY, "koala");

        MockAuthenticationManager authMgr = new MockAuthenticationManager(true);

        SiteminderAuthenticationProcessingFilter filter = new SiteminderAuthenticationProcessingFilter();
        filter.setAuthenticationManager(authMgr);
        filter.init(null);

        Authentication result = filter.attemptAuthentication(request);
        assertTrue(result != null);
        assertEquals("127.0.0.1", ((WebAuthenticationDetails) result.getDetails()).getRemoteAddress());
    }

    /**
     * Tests form null password handling.
     *
     * @throws Exception
     */
    public void testFormNullPasswordHandledGracefully() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter(SiteminderAuthenticationProcessingFilter.ACEGI_SECURITY_FORM_USERNAME_KEY, "marissa");

        MockAuthenticationManager authMgr = new MockAuthenticationManager(true);

        SiteminderAuthenticationProcessingFilter filter = new SiteminderAuthenticationProcessingFilter();
        filter.setAuthenticationManager(authMgr);
        filter.init(null);

        Authentication result = filter.attemptAuthentication(request);
        assertTrue(result != null);
    }

    /**
     * Tests form null username handling.
     *
     * @throws Exception
     */
    public void testFormNullUsernameHandledGracefully() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter(SiteminderAuthenticationProcessingFilter.ACEGI_SECURITY_FORM_PASSWORD_KEY, "koala");

        MockAuthenticationManager authMgr = new MockAuthenticationManager(true);

        SiteminderAuthenticationProcessingFilter filter = new SiteminderAuthenticationProcessingFilter();
        filter.setAuthenticationManager(authMgr);
        filter.init(null);

        Authentication result = filter.attemptAuthentication(request);
        assertTrue(result != null);
    }

    /**
     * Tests the overridden testRequiresAuthentication method.
     *
     * @throws Exception
     */
    public void testRequiresAuthentication() throws Exception {
        // Create a Siteminder-style request from an unauthenticated user for a strange URI
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        request.addHeader("SM_USER", "A123456");

        // Create the Siteminder filter, set a mock authentication manager to automatically grant access
        SiteminderAuthenticationProcessingFilter filter = new SiteminderAuthenticationProcessingFilter();
        filter.setDefaultTargetUrl("/defaultTargetUri");

        MockAuthenticationManager authMgrThatGrantsAccess = new MockAuthenticationManager(true);
        filter.setAuthenticationManager(authMgrThatGrantsAccess);

        filter.setSiteminderUsernameHeaderKey("SM_USER");
        filter.init(null);

        // Requests for an unknown URL should NOT require (re)authentication
        request.setRequestURI("http://an.unknown.url");

        boolean requiresAuthentication = filter.requiresAuthentication(request, response);
        assertFalse(requiresAuthentication);

        // Requests for the filter processing URI SHOULD require (re)authentication
        request.setRequestURI(request.getContextPath() + filter.getFilterProcessesUrl());
        requiresAuthentication = filter.requiresAuthentication(request, response);
        assertTrue(requiresAuthentication);

        // Requests for the default target URI SHOULD require (re)authentication
        request.setRequestURI(request.getContextPath() + filter.getDefaultTargetUrl());
        requiresAuthentication = filter.requiresAuthentication(request, response);
        assertTrue(requiresAuthentication);
    }

    /**
     * Tests normal Siteminder header processing.
     *
     * @throws Exception
     */
    public void testSiteminderNormalOperation() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("SM_USER", "A123456");

        MockAuthenticationManager authMgr = new MockAuthenticationManager(true);

        SiteminderAuthenticationProcessingFilter filter = new SiteminderAuthenticationProcessingFilter();
        filter.setAuthenticationManager(authMgr);
        filter.setSiteminderUsernameHeaderKey("SM_USER");
        filter.init(null);

        Authentication result = filter.attemptAuthentication(request);
        assertTrue(result != null);
        assertEquals("127.0.0.1", ((WebAuthenticationDetails) result.getDetails()).getRemoteAddress());
    }
}
