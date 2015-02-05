package org.springframework.security.web.authentication.preauth;

import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

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
        SecurityContextHolder.clearContext();
    }

    @After
    public void tearDown() {
        SecurityContextHolder.clearContext();
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

    // SEC-2045
    @Test
    public void testAfterPropertiesSetInvokesSuper() throws Exception {
        ConcretePreAuthenticatedProcessingFilter filter = new ConcretePreAuthenticatedProcessingFilter();
        AuthenticationManager am = mock(AuthenticationManager.class);
        filter.setAuthenticationManager(am);
        filter.afterPropertiesSet();
        assertTrue(filter.initFilterBeanInvoked);
    }

    @Test
    public void testDoFilterAuthenticated() throws Exception {
        testDoFilter(true);
    }

    @Test
    public void testDoFilterUnauthenticated() throws Exception {
        testDoFilter(false);
    }

    // SEC-1968
    @Test
    public void nullPreAuthenticationClearsPreviousUser() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("oldUser", "pass","ROLE_USER"));
        ConcretePreAuthenticatedProcessingFilter filter = new ConcretePreAuthenticatedProcessingFilter();
        filter.principal = null;
        filter.setCheckForPrincipalChanges(true);

        filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), new MockFilterChain());

        assertEquals(null, SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void nullPreAuthenticationPerservesPreviousUserCheckPrincipalChangesFalse() throws Exception {
        TestingAuthenticationToken authentication = new TestingAuthenticationToken("oldUser", "pass","ROLE_USER");
        SecurityContextHolder.getContext().setAuthentication(authentication);
        ConcretePreAuthenticatedProcessingFilter filter = new ConcretePreAuthenticatedProcessingFilter();
        filter.principal = null;

        filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), new MockFilterChain());

        assertEquals(authentication, SecurityContextHolder.getContext().getAuthentication());
    }

    // SEC-1869
    @Test
    public void nullSuccessHandlerDoesntHarm() throws Exception {
        MockHttpServletRequest request = createMockAuthenticationRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        Authentication authentication = new TestingAuthenticationToken("oldUser", "pass", "ROLE_USER");

        filter.setAuthenticationSuccessHandler(null);

        // be sure that this doesn't fail even though authenticationSuccessHandler is null
        filter.successfulAuthentication(request, response, authentication);

        assertEquals(authentication, SecurityContextHolder.getContext().getAuthentication());
    }

    // SEC-1869
    @Test
    public void successHandlerIsCalled() throws Exception {
        MockHttpServletRequest request = createMockAuthenticationRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        Authentication authentication = new TestingAuthenticationToken("oldUser", "pass", "ROLE_USER");

        AuthenticationSuccessHandler successHandler = mock(AuthenticationSuccessHandler.class);
        filter.setAuthenticationSuccessHandler(successHandler);

        filter.successfulAuthentication(request, response, authentication);

        verify(successHandler, times(1)).onAuthenticationSuccess(request, response, authentication);
        assertEquals(authentication, SecurityContextHolder.getContext().getAuthentication());
    }

    // SEC-1869
    @Test
    public void nullFailureHandlerDoesntHarm() throws Exception {
        MockHttpServletRequest request = createMockAuthenticationRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        AuthenticationException authExc = new PreAuthenticatedCredentialsNotFoundException("foo!");

        filter.setAuthenticationFailureHandler(null);

        // be sure that this doesn't fail even though authenticationFailureHandler is null
        filter.unsuccessfulAuthentication(request, response, authExc);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    // SEC-1869
    @Test
    public void failureHandlerIsInvoked() throws Exception {
        MockHttpServletRequest request = createMockAuthenticationRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        AuthenticationFailureHandler failureHandler = mock(AuthenticationFailureHandler.class);

        // mock an AuthenticationManager that always throws an exception
        PreAuthenticatedCredentialsNotFoundException authExc = new PreAuthenticatedCredentialsNotFoundException("");
        AuthenticationManager am = mock(AuthenticationManager.class);
        when(am.authenticate(any(Authentication.class))).thenThrow(authExc);

        filter.setAuthenticationManager(am);
        filter.setAuthenticationFailureHandler(failureHandler);
        filter.afterPropertiesSet();

        filter.doFilter(request, response, mock(FilterChain.class));

        // check that this exception causes the failure handler to be called. The exception as such
        // is not propagated, but the failure handler receives it to act on it if needed.
        verify(failureHandler, times(1)).onAuthenticationFailure(request, response, authExc);
    }

    private MockHttpServletRequest createMockAuthenticationRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        request.setServletPath("/j_mock_post");
        request.setScheme("http");
        request.setServerName("www.example.com");
        request.setRequestURI("/mycontext/j_mock_post");
        request.setContextPath("/mycontext");

        return request;
    }

    private void testDoFilter(boolean grantAccess) throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse res = new MockHttpServletResponse();
        getFilter(grantAccess).doFilter(req, res, new MockFilterChain());
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
        private String principal = "testPrincipal";
        private boolean initFilterBeanInvoked;
        protected Object getPreAuthenticatedPrincipal(HttpServletRequest httpRequest) {
            return principal;
        }
        protected Object getPreAuthenticatedCredentials(HttpServletRequest httpRequest) {
            return "testCredentials";
        }
        @Override
        protected void initFilterBean() throws ServletException {
            super.initFilterBean();
            initFilterBeanInvoked = true;
        }
    }

}
