/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.web.authentication;

import java.util.Collections;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * @author Luke Taylor
 * @since 3.0
 */
public class DefaultLoginPageGeneratingFilterTests {

	private FilterChain chain = mock(FilterChain.class);

	@Test
	public void generatingPageWithAuthenticationProcessingFilterOnlyIsSuccessFul() throws Exception {
		DefaultLoginPageGeneratingFilter filter = new DefaultLoginPageGeneratingFilter(
				new UsernamePasswordAuthenticationFilter());
		filter.doFilter(new MockHttpServletRequest("GET", "/login"), new MockHttpServletResponse(), this.chain);
		filter.doFilter(new MockHttpServletRequest("GET", "/login;pathparam=unused"), new MockHttpServletResponse(),
				this.chain);
	}

	@Test
	public void generatesForGetLogin() throws Exception {
		DefaultLoginPageGeneratingFilter filter = new DefaultLoginPageGeneratingFilter(
				new UsernamePasswordAuthenticationFilter());
		MockHttpServletResponse response = new MockHttpServletResponse();

		filter.doFilter(new MockHttpServletRequest("GET", "/login"), response, this.chain);

		assertThat(response.getContentAsString()).isNotEmpty();
	}

	@Test
	public void generatesForPostLogin() throws Exception {
		DefaultLoginPageGeneratingFilter filter = new DefaultLoginPageGeneratingFilter(
				new UsernamePasswordAuthenticationFilter());
		MockHttpServletResponse response = new MockHttpServletResponse();

		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
		filter.doFilter(request, response, this.chain);

		assertThat(response.getContentAsString()).isEmpty();
	}

	@Test
	public void generatesForNotEmptyContextLogin() throws Exception {
		DefaultLoginPageGeneratingFilter filter = new DefaultLoginPageGeneratingFilter(
				new UsernamePasswordAuthenticationFilter());
		MockHttpServletResponse response = new MockHttpServletResponse();

		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/context/login");
		request.setContextPath("/context");
		filter.doFilter(request, response, this.chain);

		assertThat(response.getContentAsString()).isNotEmpty();
	}

	@Test
	public void generatesForGetApiLogin() throws Exception {
		DefaultLoginPageGeneratingFilter filter = new DefaultLoginPageGeneratingFilter(
				new UsernamePasswordAuthenticationFilter());
		MockHttpServletResponse response = new MockHttpServletResponse();

		filter.doFilter(new MockHttpServletRequest("GET", "/api/login"), response, this.chain);

		assertThat(response.getContentAsString()).isEmpty();
	}

	@Test
	public void generatesForWithQueryMatch() throws Exception {
		DefaultLoginPageGeneratingFilter filter = new DefaultLoginPageGeneratingFilter(
				new UsernamePasswordAuthenticationFilter());
		MockHttpServletResponse response = new MockHttpServletResponse();

		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login");
		request.setQueryString("error");

		filter.doFilter(request, response, this.chain);

		assertThat(response.getContentAsString()).isNotEmpty();
	}

	@Test
	public void generatesForWithContentLength() throws Exception {
		DefaultLoginPageGeneratingFilter filter = new DefaultLoginPageGeneratingFilter(
				new UsernamePasswordAuthenticationFilter());
		filter.setOauth2LoginEnabled(true);
		filter.setOauth2AuthenticationUrlToClientName(
				Collections.singletonMap("XYUU", "\u8109\u640F\u7F51\u5E10\u6237\u767B\u5F55"));
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login");
		filter.doFilter(request, response, this.chain);
		assertThat(response
				.getContentLength() == response.getContentAsString().getBytes(response.getCharacterEncoding()).length)
						.isTrue();
	}

	@Test
	public void generatesForWithQueryNoMatch() throws Exception {
		DefaultLoginPageGeneratingFilter filter = new DefaultLoginPageGeneratingFilter(
				new UsernamePasswordAuthenticationFilter());
		MockHttpServletResponse response = new MockHttpServletResponse();

		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login");
		request.setQueryString("not");

		filter.doFilter(request, response, this.chain);

		assertThat(response.getContentAsString()).isEmpty();
	}

	@Test
	public void generatingPageWithOpenIdFilterOnlyIsSuccessFul() throws Exception {
		DefaultLoginPageGeneratingFilter filter = new DefaultLoginPageGeneratingFilter(new MockProcessingFilter());
		filter.doFilter(new MockHttpServletRequest("GET", "/login"), new MockHttpServletResponse(), this.chain);
	}

	/* SEC-1111 */
	@Test
	public void handlesNonIso8859CharsInErrorMessage() throws Exception {
		DefaultLoginPageGeneratingFilter filter = new DefaultLoginPageGeneratingFilter(
				new UsernamePasswordAuthenticationFilter());
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login");
		request.addParameter("login_error", "true");
		MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
		String message = messages.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials",
				"Bad credentials", Locale.KOREA);
		request.getSession().setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, new BadCredentialsException(message));

		filter.doFilter(request, new MockHttpServletResponse(), this.chain);
	}

	// gh-5394
	@Test
	public void generatesForOAuth2LoginAndEscapesClientName() throws Exception {
		DefaultLoginPageGeneratingFilter filter = new DefaultLoginPageGeneratingFilter();
		filter.setLoginPageUrl(DefaultLoginPageGeneratingFilter.DEFAULT_LOGIN_PAGE_URL);
		filter.setOauth2LoginEnabled(true);

		String clientName = "Google < > \" \' &";
		filter.setOauth2AuthenticationUrlToClientName(
				Collections.singletonMap("/oauth2/authorization/google", clientName));

		MockHttpServletResponse response = new MockHttpServletResponse();
		filter.doFilter(new MockHttpServletRequest("GET", "/login"), response, this.chain);

		assertThat(response.getContentAsString())
				.contains("<a href=\"/oauth2/authorization/google\">Google &lt; &gt; &quot; &#39; &amp;</a>");
	}

	@Test
	public void generatesForSaml2LoginAndEscapesClientName() throws Exception {
		DefaultLoginPageGeneratingFilter filter = new DefaultLoginPageGeneratingFilter();
		filter.setLoginPageUrl(DefaultLoginPageGeneratingFilter.DEFAULT_LOGIN_PAGE_URL);
		filter.setSaml2LoginEnabled(true);

		String clientName = "Google < > \" \' &";
		filter.setSaml2AuthenticationUrlToProviderName(Collections.singletonMap("/saml/sso/google", clientName));

		MockHttpServletResponse response = new MockHttpServletResponse();
		filter.doFilter(new MockHttpServletRequest("GET", "/login"), response, this.chain);

		assertThat(response.getContentAsString()).contains("Login with SAML 2.0");
		assertThat(response.getContentAsString())
				.contains("<a href=\"/saml/sso/google\">Google &lt; &gt; &quot; &#39; &amp;</a>");
	} // Fake OpenID filter (since it's not in this module

	@SuppressWarnings("unused")
	private static class MockProcessingFilter extends AbstractAuthenticationProcessingFilter {

		MockProcessingFilter() {
			super("/someurl");
		}

		@Override
		public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
				throws AuthenticationException {
			return null;
		}

		public String getClaimedIdentityFieldName() {
			return "unused";
		}

	}

}
