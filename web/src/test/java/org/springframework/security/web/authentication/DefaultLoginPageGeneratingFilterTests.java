package org.springframework.security.web.authentication;

import static org.mockito.Mockito.mock;

import java.util.Locale;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;

/**
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
public class DefaultLoginPageGeneratingFilterTests {
    FilterChain chain = mock(FilterChain.class);

    @Test
    public void generatingPageWithAuthenticationProcessingFilterOnlyIsSuccessFul() throws Exception {
        DefaultLoginPageGeneratingFilter filter = new DefaultLoginPageGeneratingFilter(new UsernamePasswordAuthenticationFilter());
        filter.doFilter(new MockHttpServletRequest("GET", "/spring_security_login"), new MockHttpServletResponse(), chain);
        filter.doFilter(new MockHttpServletRequest("GET", "/spring_security_login;pathparam=unused"), new MockHttpServletResponse(), chain);
    }


    @Test
    public void generatingPageWithOpenIdFilterOnlyIsSuccessFul() throws Exception {
        DefaultLoginPageGeneratingFilter filter = new DefaultLoginPageGeneratingFilter(new MockProcessingFilter());
        filter.doFilter(new MockHttpServletRequest("GET", "/spring_security_login"), new MockHttpServletResponse(), chain);
    }

    // Fake OpenID filter (since it's not in this module
    private static class MockProcessingFilter extends AbstractAuthenticationProcessingFilter {
        protected MockProcessingFilter() {
            super("/someurl");
        }

        @Override
        public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
            return null;
        }

        public String getClaimedIdentityFieldName() {
            return "unused";
        }
    }

    /* SEC-1111 */
    @Test
    public void handlesNonIso8859CharsInErrorMessage() throws Exception {
        DefaultLoginPageGeneratingFilter filter = new DefaultLoginPageGeneratingFilter(new UsernamePasswordAuthenticationFilter());
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/spring_security_login");
        request.addParameter("login_error", "true");
        MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
        String message = messages.getMessage(
                "AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials", Locale.KOREA);
        System.out.println("Message: " + message);
        request.getSession().setAttribute(AbstractAuthenticationProcessingFilter.SPRING_SECURITY_LAST_EXCEPTION_KEY, new BadCredentialsException(message));

        filter.doFilter(request, new MockHttpServletResponse(), chain);
    }
}
