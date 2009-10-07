package org.springframework.security.web.authentication.preauth;

import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;

import org.junit.Before;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class AbstractPreAuthenticatedProcessingFilterTests {
    private AbstractPreAuthenticatedProcessingFilter filter;

    @Before
    public void createFilter() {
        filter = new AbstractPreAuthenticatedProcessingFilter() {
            protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
                return "n/a";
            }

            protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
                return "doesntmatter";
            }
        };
        SecurityContextHolder.getContext().setAuthentication(null);
    }

    @Test
    public void filterChainProceedsOnFailedAuthenticationByDefault() throws Exception {
        AuthenticationManager am = mock(AuthenticationManager.class);
        when(am.authenticate(any(Authentication.class))).thenThrow(new BadCredentialsException(""));
        filter.setAuthenticationManager(am);
        filter.afterPropertiesSet();
        filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), mock(FilterChain.class));
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    /* SEC-881 */
    @Test(expected=BadCredentialsException.class)
    public void exceptionIsThrownOnFailedAuthenticationIfContinueFilterChainOnUnsuccessfulAuthenticationSetToFalse() throws Exception {
        AuthenticationManager am = mock(AuthenticationManager.class);
        when(am.authenticate(any(Authentication.class))).thenThrow(new BadCredentialsException(""));
        filter.setContinueFilterChainOnUnsuccessfulAuthentication(false);
        filter.setAuthenticationManager(am);
        filter.afterPropertiesSet();
        filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), mock(FilterChain.class));
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void testAfterPropertiesSet() {
        ConcretePreAuthenticatedProcessingFilter filter = new ConcretePreAuthenticatedProcessingFilter();
        try {
            filter.afterPropertiesSet();
            fail("AfterPropertiesSet didn't throw expected exception");
        } catch (IllegalArgumentException expected) {
        } catch (Exception unexpected) {
            fail("AfterPropertiesSet throws unexpected exception");
        }
    }

    @Test
    public void testDoFilterAuthenticated() throws Exception {
        testDoFilter(true);
    }

    @Test
    public void testDoFilterUnauthenticated() throws Exception {
        testDoFilter(false);
    }

    private void testDoFilter(boolean grantAccess) throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse res = new MockHttpServletResponse();
        getFilter(grantAccess).doFilter(req,res,new MockFilterChain());
        assertEquals(grantAccess, null != SecurityContextHolder.getContext().getAuthentication());
    }

    private static ConcretePreAuthenticatedProcessingFilter getFilter(boolean grantAccess) throws Exception {
        ConcretePreAuthenticatedProcessingFilter filter = new ConcretePreAuthenticatedProcessingFilter();
        AuthenticationManager am = mock(AuthenticationManager.class);

        if (!grantAccess) {
            when(am.authenticate(any(Authentication.class))).thenThrow(new BadCredentialsException(""));
        } else {
            when(am.authenticate(any(Authentication.class))).thenAnswer(new Answer<Authentication>() {
                public Authentication answer(InvocationOnMock invocation) throws Throwable {
                    return (Authentication) invocation.getArguments()[0];
                }
            });
        }

        filter.setAuthenticationManager(am);
        filter.afterPropertiesSet();
        return filter;
    }

    private static class ConcretePreAuthenticatedProcessingFilter extends AbstractPreAuthenticatedProcessingFilter {
        protected Object getPreAuthenticatedPrincipal(HttpServletRequest httpRequest) {
            return "testPrincipal";
        }
        protected Object getPreAuthenticatedCredentials(HttpServletRequest httpRequest) {
            return "testCredentials";
        }
    }

}
