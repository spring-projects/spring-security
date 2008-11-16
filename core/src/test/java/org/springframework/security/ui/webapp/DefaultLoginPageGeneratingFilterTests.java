package org.springframework.security.ui.webapp;

import static org.junit.Assert.*;

import javax.servlet.http.HttpServletRequest;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.util.MockFilterChain;
import org.springframework.security.ui.AbstractProcessingFilter;
import org.springframework.security.ui.FilterChainOrder;

/**
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.5
 */
public class DefaultLoginPageGeneratingFilterTests {

    @Test
    public void generatingPageWithAuthenticationProcessingFilterOnlyIsSuccessFul() throws Exception {
        DefaultLoginPageGeneratingFilter filter = new DefaultLoginPageGeneratingFilter(new AuthenticationProcessingFilter());
        filter.doFilter(new MockHttpServletRequest("GET", "/spring_security_login"), new MockHttpServletResponse(), new MockFilterChain(false));
        filter.doFilter(new MockHttpServletRequest("GET", "/spring_security_login;pathparam=unused"), new MockHttpServletResponse(), new MockFilterChain(false));
    }


    @Test
    public void generatingPageWithOpenIdFilterOnlyIsSuccessFul() throws Exception {
        DefaultLoginPageGeneratingFilter filter = new DefaultLoginPageGeneratingFilter(new MockProcessingFilter());
        filter.doFilter(new MockHttpServletRequest("GET", "/spring_security_login"), new MockHttpServletResponse(), new MockFilterChain(false));
    }

    private static class MockProcessingFilter extends AbstractProcessingFilter {

        @Override
        public Authentication attemptAuthentication(HttpServletRequest request) throws AuthenticationException {
            return null;
        }

        @Override
        public String getDefaultFilterProcessesUrl() {
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
