package org.springframework.security.web.authentication.preauth;

import static org.junit.Assert.assertNull;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;

import org.junit.Before;
import org.junit.Test;
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

}
