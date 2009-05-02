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

package org.springframework.security.web.intercept;

import static org.junit.Assert.*;
import static org.mockito.Matchers.*;
import static org.mockito.Mockito.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.MockApplicationEventPublisher;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.intercept.RunAsManager;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;


/**
 * Tests {@link org.springframework.security.web.intercept.WebInvocationPrivilegeEvaluator}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class WebInvocationPrivilegeEvaluatorTests {
    private AccessDecisionManager adm;
    private FilterInvocationSecurityMetadataSource ods;
    private RunAsManager ram;
    private FilterSecurityInterceptor interceptor;

    //~ Methods ========================================================================================================

    @Before
    public final void setUp() {
        interceptor = new FilterSecurityInterceptor();
        ods = mock(FilterInvocationSecurityMetadataSource.class);
        adm = mock(AccessDecisionManager.class);
        ram = mock(RunAsManager.class);
        interceptor.setAuthenticationManager(mock(AuthenticationManager.class));
        interceptor.setSecurityMetadataSource(ods);
        interceptor.setAccessDecisionManager(adm);
        interceptor.setRunAsManager(ram);
        interceptor.setApplicationEventPublisher(new MockApplicationEventPublisher(true));
        SecurityContextHolder.clearContext();
    }

    @Test
    public void permitsAccessIfNoMatchingAttributesAndPublicInvocationsAllowed() throws Exception {
        WebInvocationPrivilegeEvaluator wipe = new WebInvocationPrivilegeEvaluator(interceptor);
        when(ods.getAttributes(anyObject())).thenReturn(null);
        assertTrue(wipe.isAllowed("/context", "/foo/index.jsp", "GET", mock(Authentication.class)));
    }

    @Test
    public void deniesAccessIfNoMatchingAttributesAndPublicInvocationsNotAllowed() throws Exception {
        WebInvocationPrivilegeEvaluator wipe = new WebInvocationPrivilegeEvaluator(interceptor);
        when(ods.getAttributes(anyObject())).thenReturn(null);
        interceptor.setRejectPublicInvocations(true);
        assertFalse(wipe.isAllowed("/context", "/foo/index.jsp", "GET", mock(Authentication.class)));
    }

    @Test
    public void deniesAccessIfAuthenticationIsNull() throws Exception {
        WebInvocationPrivilegeEvaluator wipe = new WebInvocationPrivilegeEvaluator(interceptor);
        assertFalse(wipe.isAllowed("/foo/index.jsp", null));
    }

    @Test
    public void allowsAccessIfAccessDecisionMangerDoes() throws Exception {
        Authentication token = new TestingAuthenticationToken("test", "Password", "MOCK_INDEX");
        WebInvocationPrivilegeEvaluator wipe = new WebInvocationPrivilegeEvaluator(interceptor);
        assertTrue(wipe.isAllowed("/foo/index.jsp", token));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void deniesAccessIfAccessDecisionMangerDoes() throws Exception {
        Authentication token = new TestingAuthenticationToken("test", "Password", "MOCK_INDEX");
        WebInvocationPrivilegeEvaluator wipe = new WebInvocationPrivilegeEvaluator(interceptor);

        doThrow(new AccessDeniedException("")).when(adm).decide(any(Authentication.class), anyObject(), anyList());

        assertFalse(wipe.isAllowed("/foo/index.jsp", token));
    }

    @Test(expected=UnsupportedOperationException.class)
    public void dummyChainRejectsInvocation() throws Exception {
        WebInvocationPrivilegeEvaluator.DUMMY_CHAIN.doFilter(mock(HttpServletRequest.class), mock(HttpServletResponse.class));
    }
}
