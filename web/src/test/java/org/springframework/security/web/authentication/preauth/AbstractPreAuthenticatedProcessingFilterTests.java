package org.springframework.security.web.authentication.preauth;

import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.mock;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.BadCredentialsException;
import org.springframework.security.MockAuthenticationManager;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

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

            public int getOrder() {
                return 0;
            }
        };
        SecurityContextHolder.getContext().setAuthentication(null);
    }

    @Test
    public void filterChainProceedsOnFailedAuthenticationByDefault() throws Exception {
        filter.setAuthenticationManager(new MockAuthenticationManager(false));
        filter.afterPropertiesSet();
        filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), mock(FilterChain.class));
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    /* SEC-881 */
    @Test(expected=BadCredentialsException.class)
    public void exceptionIsThrownOnFailedAuthenticationIfContinueFilterChainOnUnsuccessfulAuthenticationSetToFalse() throws Exception {
        filter.setContinueFilterChainOnUnsuccessfulAuthentication(false);
        filter.setAuthenticationManager(new MockAuthenticationManager(false));
        filter.afterPropertiesSet();
        filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), mock(FilterChain.class));
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

}
