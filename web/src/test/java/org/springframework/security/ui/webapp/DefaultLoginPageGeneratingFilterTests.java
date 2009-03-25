package org.springframework.security.ui.webapp;

import static org.mockito.Mockito.mock;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.ui.AbstractProcessingFilter;
import org.springframework.security.ui.FilterChainOrder;

/**
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.5
 */
public class DefaultLoginPageGeneratingFilterTests {
    FilterChain chain = mock(FilterChain.class);

    @Test
    public void generatingPageWithAuthenticationProcessingFilterOnlyIsSuccessFul() throws Exception {
        DefaultLoginPageGeneratingFilter filter = new DefaultLoginPageGeneratingFilter(new AuthenticationProcessingFilter());
        filter.doFilter(new MockHttpServletRequest("GET", "/spring_security_login"), new MockHttpServletResponse(), chain);
        filter.doFilter(new MockHttpServletRequest("GET", "/spring_security_login;pathparam=unused"), new MockHttpServletResponse(), chain);
    }


    @Test
    public void generatingPageWithOpenIdFilterOnlyIsSuccessFul() throws Exception {
        DefaultLoginPageGeneratingFilter filter = new DefaultLoginPageGeneratingFilter(new MockProcessingFilter());
        filter.doFilter(new MockHttpServletRequest("GET", "/spring_security_login"), new MockHttpServletResponse(), chain);
    }

    // Fake OpenID filter (since it's not in this module
    private static class MockProcessingFilter extends AbstractProcessingFilter {
        protected MockProcessingFilter() {
            super("/someurl");
        }

        @Override
        public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
            return null;
        }

        public int getOrder() {
            return FilterChainOrder.AUTHENTICATION_PROCESSING_FILTER;
        }

        public String getClaimedIdentityFieldName() {
            return "unused";
        }
    }
}
