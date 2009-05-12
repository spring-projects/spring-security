/*
 * Copyright 2005-2007 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.portlet;

import javax.portlet.PortletSession;

import junit.framework.TestCase;

import org.springframework.mock.web.portlet.MockActionRequest;
import org.springframework.mock.web.portlet.MockActionResponse;
import org.springframework.mock.web.portlet.MockRenderRequest;
import org.springframework.mock.web.portlet.MockRenderResponse;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

/**
 * Tests {@link PortletSessionContextIntegrationInterceptor}.
 *
 * @author John A. Lewis
 * @since 2.0
 * @version $Id$
 */
public class PortletSessionContextIntegrationInterceptorTests extends TestCase {

    //~ Methods ========================================================================================================

    public void setUp() throws Exception {
        super.setUp();
        SecurityContextHolder.clearContext();
    }

    public void tearDown() throws Exception {
        super.tearDown();
        SecurityContextHolder.clearContext();
    }

    public void testDetectsIncompatibleSessionProperties() throws Exception {
        PortletSessionContextIntegrationInterceptor interceptor = new PortletSessionContextIntegrationInterceptor();
        try {
            interceptor.setAllowSessionCreation(false);
            interceptor.setForceEagerSessionCreation(true);
            interceptor.afterPropertiesSet();
            fail("Shown have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            // ignore
        }
        interceptor.setAllowSessionCreation(true);
        interceptor.afterPropertiesSet();
    }

    public void testNormalRenderRequestProcessing() throws Exception {

        // Build an Authentication object we simulate came from PortletSession
        PreAuthenticatedAuthenticationToken sessionPrincipal = PortletTestUtils.createAuthenticatedToken();
        PreAuthenticatedAuthenticationToken baselinePrincipal = PortletTestUtils.createAuthenticatedToken();

        // Build a Context to store in PortletSession (simulating prior request)
        SecurityContext sc = new SecurityContextImpl();
        sc.setAuthentication(sessionPrincipal);

        // Build mock request and response
        MockRenderRequest request = PortletTestUtils.createRenderRequest();
        MockRenderResponse response = PortletTestUtils.createRenderResponse();
        request.getPortletSession().setAttribute(
                PortletSessionContextIntegrationInterceptor.SPRING_SECURITY_CONTEXT_KEY,
                sc, PortletSession.APPLICATION_SCOPE);

        // Prepare interceptor
        PortletSessionContextIntegrationInterceptor interceptor = new PortletSessionContextIntegrationInterceptor();
        interceptor.afterPropertiesSet();

        // Verify the SecurityContextHolder starts empty
        assertNull(SecurityContextHolder.getContext().getAuthentication());

        // Run preHandleRender phase and verify SecurityContextHolder contains our Authentication
        interceptor.preHandleRender(request, response, null);
        assertEquals(baselinePrincipal, SecurityContextHolder.getContext().getAuthentication());

        // Run postHandleRender phase and verify the SecurityContextHolder still contains our Authentication
        interceptor.postHandleRender(request, response, null, null);
        assertEquals(baselinePrincipal, SecurityContextHolder.getContext().getAuthentication());

        // Run afterRenderCompletion phase and verify the SecurityContextHolder is empty
        interceptor.afterRenderCompletion(request, response, null, null);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    public void testNormalActionRequestProcessing() throws Exception {

        // Build an Authentication object we simulate came from PortletSession
        PreAuthenticatedAuthenticationToken sessionPrincipal = PortletTestUtils.createAuthenticatedToken();
        PreAuthenticatedAuthenticationToken baselinePrincipal = PortletTestUtils.createAuthenticatedToken();

        // Build a Context to store in PortletSession (simulating prior request)
        SecurityContext sc = new SecurityContextImpl();
        sc.setAuthentication(sessionPrincipal);

        // Build mock request and response
        MockActionRequest request = PortletTestUtils.createActionRequest();
        MockActionResponse response = PortletTestUtils.createActionResponse();
        request.getPortletSession().setAttribute(
                PortletSessionContextIntegrationInterceptor.SPRING_SECURITY_CONTEXT_KEY,
                sc, PortletSession.APPLICATION_SCOPE);

        // Prepare interceptor
        PortletSessionContextIntegrationInterceptor interceptor = new PortletSessionContextIntegrationInterceptor();
        interceptor.afterPropertiesSet();

        // Verify the SecurityContextHolder starts empty
        assertNull(SecurityContextHolder.getContext().getAuthentication());

        // Run preHandleAction phase and verify SecurityContextHolder contains our Authentication
        interceptor.preHandleAction(request, response, null);
        assertEquals(baselinePrincipal, SecurityContextHolder.getContext().getAuthentication());

        // Run afterActionCompletion phase and verify the SecurityContextHolder is empty
        interceptor.afterActionCompletion(request, response, null, null);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    public void testUpdatesCopiedBackIntoSession() throws Exception {

        // Build an Authentication object we simulate came from PortletSession
        PreAuthenticatedAuthenticationToken sessionPrincipal = PortletTestUtils.createAuthenticatedToken();
        PreAuthenticatedAuthenticationToken baselinePrincipal = PortletTestUtils.createAuthenticatedToken();

        // Build a Context to store in PortletSession (simulating prior request)
        SecurityContext sc = new SecurityContextImpl();
        sc.setAuthentication(sessionPrincipal);

        // Build mock request and response
        MockActionRequest request = PortletTestUtils.createActionRequest();
        MockActionResponse response = PortletTestUtils.createActionResponse();
        request.getPortletSession().setAttribute(
                PortletSessionContextIntegrationInterceptor.SPRING_SECURITY_CONTEXT_KEY,
                sc, PortletSession.APPLICATION_SCOPE);

        // Prepare interceptor
        PortletSessionContextIntegrationInterceptor interceptor = new PortletSessionContextIntegrationInterceptor();
        interceptor.afterPropertiesSet();

        // Verify the SecurityContextHolder starts empty
        assertNull(SecurityContextHolder.getContext().getAuthentication());

        // Run preHandleAction phase and verify SecurityContextHolder contains our Authentication
        interceptor.preHandleAction(request, response, null);
        assertEquals(baselinePrincipal, SecurityContextHolder.getContext().getAuthentication());

        // Perform updates to principal
        sessionPrincipal = PortletTestUtils.createAuthenticatedToken(
                new User(PortletTestUtils.TESTUSER, PortletTestUtils.TESTCRED, true, true, true, true,
                        AuthorityUtils.createAuthorityList("UPDATEDROLE1")));
        baselinePrincipal = PortletTestUtils.createAuthenticatedToken(
                new User(PortletTestUtils.TESTUSER, PortletTestUtils.TESTCRED, true, true, true, true,
                        AuthorityUtils.createAuthorityList("UPDATEDROLE1")));

        // Store updated principal into SecurityContextHolder
        SecurityContextHolder.getContext().setAuthentication(sessionPrincipal);

        // Run afterActionCompletion phase and verify the SecurityContextHolder is empty
        interceptor.afterActionCompletion(request, response, null, null);
        assertNull(SecurityContextHolder.getContext().getAuthentication());

        // Verify the new principal is stored in the session
        sc = (SecurityContext)request.getPortletSession().getAttribute(
                PortletSessionContextIntegrationInterceptor.SPRING_SECURITY_CONTEXT_KEY,
                PortletSession.APPLICATION_SCOPE);
        assertEquals(baselinePrincipal, sc.getAuthentication());
    }

    public void testPortletSessionCreatedWhenContextHolderChanges() throws Exception {

        // Build mock request and response
        MockActionRequest request = PortletTestUtils.createActionRequest();
        MockActionResponse response = PortletTestUtils.createActionResponse();

        // Prepare the interceptor
        PortletSessionContextIntegrationInterceptor interceptor = new PortletSessionContextIntegrationInterceptor();
        interceptor.afterPropertiesSet();

        // Execute the interceptor
        interceptor.preHandleAction(request, response, null);
        PreAuthenticatedAuthenticationToken principal = PortletTestUtils.createAuthenticatedToken();
        SecurityContextHolder.getContext().setAuthentication(principal);
        interceptor.afterActionCompletion(request, response, null, null);

        // Verify Authentication is in the PortletSession
        SecurityContext sc = (SecurityContext)request.getPortletSession(false).
                getAttribute(PortletSessionContextIntegrationInterceptor.SPRING_SECURITY_CONTEXT_KEY, PortletSession.APPLICATION_SCOPE);
        assertEquals(principal, ((SecurityContext)sc).getAuthentication());
    }

    public void testPortletSessionEagerlyCreatedWhenDirected() throws Exception {

        // Build mock request and response
        MockActionRequest request = PortletTestUtils.createActionRequest();
        MockActionResponse response = PortletTestUtils.createActionResponse();

        // Prepare the interceptor
        PortletSessionContextIntegrationInterceptor interceptor = new PortletSessionContextIntegrationInterceptor();
        interceptor.setForceEagerSessionCreation(true); // non-default
        interceptor.afterPropertiesSet();

        // Execute the interceptor
        interceptor.preHandleAction(request, response, null);
        interceptor.afterActionCompletion(request, response, null, null);

        // Check the session is not null
        assertNotNull(request.getPortletSession(false));
    }

    public void testPortletSessionNotCreatedUnlessContextHolderChanges() throws Exception {

        // Build mock request and response
        MockActionRequest request = PortletTestUtils.createActionRequest();
        MockActionResponse response = PortletTestUtils.createActionResponse();

        // Prepare the interceptor
        PortletSessionContextIntegrationInterceptor interceptor = new PortletSessionContextIntegrationInterceptor();
        interceptor.afterPropertiesSet();

        // Execute the interceptor
        interceptor.preHandleAction(request, response, null);
        interceptor.afterActionCompletion(request, response, null, null);

        // Check the session is null
        assertNull(request.getPortletSession(false));
    }

    public void testPortletSessionWithNonContextInWellKnownLocationIsOverwritten()
            throws Exception {

        // Build mock request and response
        MockActionRequest request = PortletTestUtils.createActionRequest();
        MockActionResponse response = PortletTestUtils.createActionResponse();
        request.getPortletSession().setAttribute(
                PortletSessionContextIntegrationInterceptor.SPRING_SECURITY_CONTEXT_KEY,
                "NOT_A_CONTEXT_OBJECT", PortletSession.APPLICATION_SCOPE);

        // Prepare the interceptor
        PortletSessionContextIntegrationInterceptor interceptor = new PortletSessionContextIntegrationInterceptor();
        interceptor.afterPropertiesSet();

        // Execute the interceptor
        interceptor.preHandleAction(request, response, null);
        PreAuthenticatedAuthenticationToken principal = PortletTestUtils.createAuthenticatedToken();
        SecurityContextHolder.getContext().setAuthentication(principal);
        interceptor.afterActionCompletion(request, response, null, null);

        // Verify Authentication is in the PortletSession
        SecurityContext sc = (SecurityContext)request.getPortletSession(false).
                getAttribute(PortletSessionContextIntegrationInterceptor.SPRING_SECURITY_CONTEXT_KEY, PortletSession.APPLICATION_SCOPE);
        assertEquals(principal, ((SecurityContext)sc).getAuthentication());
    }

    public void testPortletSessionCreationNotAllowed() throws Exception {

        // Build mock request and response
        MockActionRequest request = PortletTestUtils.createActionRequest();
        MockActionResponse response = PortletTestUtils.createActionResponse();

        // Prepare the interceptor
        PortletSessionContextIntegrationInterceptor interceptor = new PortletSessionContextIntegrationInterceptor();
        interceptor.setAllowSessionCreation(false); // non-default
        interceptor.afterPropertiesSet();

        // Execute the interceptor
        interceptor.preHandleAction(request, response, null);
        PreAuthenticatedAuthenticationToken principal = PortletTestUtils.createAuthenticatedToken();
        SecurityContextHolder.getContext().setAuthentication(principal);
        interceptor.afterActionCompletion(request, response, null, null);

        // Check the session is null
        assertNull(request.getPortletSession(false));
    }

    public void testUsePortletScopeSession() throws Exception {

        // Build an Authentication object we simulate came from PortletSession
        PreAuthenticatedAuthenticationToken sessionPrincipal = PortletTestUtils.createAuthenticatedToken();
        PreAuthenticatedAuthenticationToken baselinePrincipal = PortletTestUtils.createAuthenticatedToken();

        // Build a Context to store in PortletSession (simulating prior request)
        SecurityContext sc = new SecurityContextImpl();
        sc.setAuthentication(sessionPrincipal);

        // Build mock request and response
        MockActionRequest request = PortletTestUtils.createActionRequest();
        MockActionResponse response = PortletTestUtils.createActionResponse();
        request.getPortletSession().setAttribute(
                PortletSessionContextIntegrationInterceptor.SPRING_SECURITY_CONTEXT_KEY,
                sc, PortletSession.PORTLET_SCOPE);

        // Prepare interceptor
        PortletSessionContextIntegrationInterceptor interceptor = new PortletSessionContextIntegrationInterceptor();
        interceptor.setUseApplicationScopePortletSession(false); // non-default
        interceptor.afterPropertiesSet();

        // Run preHandleAction phase and verify SecurityContextHolder contains our Authentication
        interceptor.preHandleAction(request, response, null);
        assertEquals(baselinePrincipal, SecurityContextHolder.getContext().getAuthentication());

        // Perform updates to principal
        sessionPrincipal = PortletTestUtils.createAuthenticatedToken(
                new User(PortletTestUtils.TESTUSER, PortletTestUtils.TESTCRED, true, true, true, true,
                        AuthorityUtils.createAuthorityList("UPDATEDROLE1")));
        baselinePrincipal = PortletTestUtils.createAuthenticatedToken(
                new User(PortletTestUtils.TESTUSER, PortletTestUtils.TESTCRED, true, true, true, true,
                        AuthorityUtils.createAuthorityList("UPDATEDROLE1")));

        // Store updated principal into SecurityContextHolder
        SecurityContextHolder.getContext().setAuthentication(sessionPrincipal);

        // Run afterActionCompletion phase and verify the SecurityContextHolder is empty
        interceptor.afterActionCompletion(request, response, null, null);
        assertNull(SecurityContextHolder.getContext().getAuthentication());

        // Verify the new principal is stored in the session
        sc = (SecurityContext)request.getPortletSession().getAttribute(
                PortletSessionContextIntegrationInterceptor.SPRING_SECURITY_CONTEXT_KEY,
                PortletSession.PORTLET_SCOPE);
        assertEquals(baselinePrincipal, sc.getAuthentication());
    }


}
