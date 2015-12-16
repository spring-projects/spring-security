package org.springframework.security.web.authentication;

import static org.assertj.core.api.Assertions.assertThat;
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
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;

/**
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class DefaultLoginPageGeneratingFilterTests {
	FilterChain chain = mock(FilterChain.class);

	@Test
	public void generatingPageWithAuthenticationProcessingFilterOnlyIsSuccessFul()
			throws Exception {
		DefaultLoginPageGeneratingFilter filter = new DefaultLoginPageGeneratingFilter(
				new UsernamePasswordAuthenticationFilter());
		filter.doFilter(new MockHttpServletRequest("GET", "/login"),
				new MockHttpServletResponse(), chain);
		filter.doFilter(new MockHttpServletRequest("GET", "/login;pathparam=unused"),
				new MockHttpServletResponse(), chain);
	}

	@Test
	public void generatesForGetLogin() throws Exception {
		DefaultLoginPageGeneratingFilter filter = new DefaultLoginPageGeneratingFilter(
				new UsernamePasswordAuthenticationFilter());
		MockHttpServletResponse response = new MockHttpServletResponse();

		filter.doFilter(new MockHttpServletRequest("GET", "/login"), response, chain);

		assertThat(response.getContentAsString()).isNotEmpty();
	}

	@Test
	public void generatesForPostLogin() throws Exception {
		DefaultLoginPageGeneratingFilter filter = new DefaultLoginPageGeneratingFilter(
				new UsernamePasswordAuthenticationFilter());
		MockHttpServletResponse response = new MockHttpServletResponse();

		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
		filter.doFilter(request, response, chain);

		assertThat(response.getContentAsString()).isEmpty();
	}

	@Test
	public void generatesForNotEmptyContextLogin() throws Exception {
		DefaultLoginPageGeneratingFilter filter = new DefaultLoginPageGeneratingFilter(
				new UsernamePasswordAuthenticationFilter());
		MockHttpServletResponse response = new MockHttpServletResponse();

		MockHttpServletRequest request = new MockHttpServletRequest("GET",
				"/context/login");
		request.setContextPath("/context");
		filter.doFilter(request, response, chain);

		assertThat(response.getContentAsString()).isNotEmpty();
	}

	@Test
	public void generatesForGetApiLogin() throws Exception {
		DefaultLoginPageGeneratingFilter filter = new DefaultLoginPageGeneratingFilter(
				new UsernamePasswordAuthenticationFilter());
		MockHttpServletResponse response = new MockHttpServletResponse();

		filter.doFilter(new MockHttpServletRequest("GET", "/api/login"), response, chain);

		assertThat(response.getContentAsString()).isEmpty();
	}

	@Test
	public void generatesForWithQueryMatch() throws Exception {
		DefaultLoginPageGeneratingFilter filter = new DefaultLoginPageGeneratingFilter(
				new UsernamePasswordAuthenticationFilter());
		MockHttpServletResponse response = new MockHttpServletResponse();

		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login");
		request.setQueryString("error");

		filter.doFilter(request, response, chain);

		assertThat(response.getContentAsString()).isNotEmpty();
	}

	@Test
	public void generatesForWithQueryNoMatch() throws Exception {
		DefaultLoginPageGeneratingFilter filter = new DefaultLoginPageGeneratingFilter(
				new UsernamePasswordAuthenticationFilter());
		MockHttpServletResponse response = new MockHttpServletResponse();

		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login");
		request.setQueryString("not");

		filter.doFilter(request, response, chain);

		assertThat(response.getContentAsString()).isEmpty();
	}

	@Test
	public void generatingPageWithOpenIdFilterOnlyIsSuccessFul() throws Exception {
		DefaultLoginPageGeneratingFilter filter = new DefaultLoginPageGeneratingFilter(
				new MockProcessingFilter());
		filter.doFilter(new MockHttpServletRequest("GET", "/login"),
				new MockHttpServletResponse(), chain);
	}

	// Fake OpenID filter (since it's not in this module
	@SuppressWarnings("unused")
	private static class MockProcessingFilter extends
			AbstractAuthenticationProcessingFilter {
		protected MockProcessingFilter() {
			super("/someurl");
		}

		@Override
		public Authentication attemptAuthentication(HttpServletRequest request,
				HttpServletResponse response) throws AuthenticationException {
			return null;
		}

		public String getClaimedIdentityFieldName() {
			return "unused";
		}
	}

	/* SEC-1111 */
	@Test
	public void handlesNonIso8859CharsInErrorMessage() throws Exception {
		DefaultLoginPageGeneratingFilter filter = new DefaultLoginPageGeneratingFilter(
				new UsernamePasswordAuthenticationFilter());
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login");
		request.addParameter("login_error", "true");
		MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
		String message = messages.getMessage(
				"AbstractUserDetailsAuthenticationProvider.badCredentials",
				"Bad credentials", Locale.KOREA);
		request.getSession().setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION,
				new BadCredentialsException(message));

		filter.doFilter(request, new MockHttpServletResponse(), chain);
	}
}
