/*
 * Copyright 2002-2024 the original author or authors.
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

import java.io.IOException;
import java.util.Collections;
import java.util.Locale;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.Test;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
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

	/* SEC-1111 */
	@Test
	public void handlesNonIso8859CharsInErrorMessage() throws Exception {
		DefaultLoginPageGeneratingFilter filter = new DefaultLoginPageGeneratingFilter(
				new UsernamePasswordAuthenticationFilter());
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login");
		MockHttpServletResponse response = new MockHttpServletResponse();
		request.setQueryString("error");
		MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
		String message = messages.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials",
				"Bad credentials", Locale.KOREA);
		request.getSession().setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, new BadCredentialsException(message));
		filter.doFilter(request, response, this.chain);
		assertThat(response.getContentAsString()).contains(message);
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
	}

	// gh-13768
	@Test
	public void generatesWhenExceptionWithEmptyMessageThenInvalidCredentials() throws Exception {
		DefaultLoginPageGeneratingFilter filter = new DefaultLoginPageGeneratingFilter(
				new UsernamePasswordAuthenticationFilter());
		filter.setLoginPageUrl(DefaultLoginPageGeneratingFilter.DEFAULT_LOGIN_PAGE_URL);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login");
		request.setQueryString("error");
		request.getSession().setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, new BadCredentialsException(null));
		MockHttpServletResponse response = new MockHttpServletResponse();
		filter.doFilter(request, response, this.chain);
		assertThat(response.getContentAsString()).contains("Invalid credentials");
	}

	@Test
	public void generateWhenOneTimeTokenLoginThenOttForm() throws Exception {
		DefaultLoginPageGeneratingFilter filter = new DefaultLoginPageGeneratingFilter();
		filter.setLoginPageUrl(DefaultLoginPageGeneratingFilter.DEFAULT_LOGIN_PAGE_URL);
		filter.setOneTimeTokenEnabled(true);
		filter.setOneTimeTokenGenerationUrl("/ott/authenticate");
		MockHttpServletResponse response = new MockHttpServletResponse();
		filter.doFilter(new MockHttpServletRequest("GET", "/login"), response, this.chain);
		assertThat(response.getContentAsString()).contains("Request a One-Time Token");
		assertThat(response.getContentAsString()).contains("""
				      <form id="ott-form" class="login-form" method="post" action="/ott/authenticate">
				        <h2>Request a One-Time Token</h2>

				        <p>
				          <label for="ott-username" class="screenreader">Username</label>
				          <input type="text" id="ott-username" name="username" placeholder="Username" required>
				        </p>

				        <button class="primary" type="submit" form="ott-form">Send Token</button>
				      </form>
				""");
	}

	@Test
	void generatesThenRenders() throws ServletException, IOException {
		DefaultLoginPageGeneratingFilter filter = new DefaultLoginPageGeneratingFilter(
				new UsernamePasswordAuthenticationFilter());
		filter.setLoginPageUrl(DefaultLoginPageGeneratingFilter.DEFAULT_LOGIN_PAGE_URL);
		filter.setSaml2LoginEnabled(true);
		String clientName = "Google < > \" \' &";
		filter.setSaml2AuthenticationUrlToProviderName(Collections.singletonMap("/saml/sso/google", clientName));
		filter.setOauth2LoginEnabled(true);
		clientName = "Google < > \" \' &";
		filter.setOauth2AuthenticationUrlToClientName(
				Collections.singletonMap("/oauth2/authorization/google", clientName));

		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login");
		request.setQueryString("error");
		MockHttpServletResponse response = new MockHttpServletResponse();
		request.getSession()
			.setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, new BadCredentialsException("Bad credentials"));
		filter.doFilter(request, response, this.chain);
		assertThat(response.getContentAsString()).isEqualTo("""
				<!DOCTYPE html>
				<html lang="en">
				  <head>
				    <meta charset="utf-8">
				    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
				    <meta name="description" content="">
				    <meta name="author" content="">
				    <title>Please sign in</title>
				    <link href="/default-ui.css" rel="stylesheet" />
				  </head>
				  <body>
				    <div class="content">
				      <form class="login-form" method="post" action="null">
				        <h2>Please sign in</h2>
				<div class="alert alert-danger" role="alert">Bad credentials</div>
				        <p>
				          <label for="username" class="screenreader">Username</label>
				          <input type="text" id="username" name="username" placeholder="Username" required autofocus>
				        </p>
				        <p>
				          <label for="password" class="screenreader">Password</label>
				          <input type="password" id="password" name="password" placeholder="Password" required>
				        </p>


				        <button type="submit" class="primary">Sign in</button>
				      </form>

				<h2>Login with OAuth 2.0</h2>
				<div class="alert alert-danger" role="alert">Bad credentials</div>
				<table class="table table-striped">
				  <tr><td><a href="/oauth2/authorization/google">Google &lt; &gt; &quot; &#39; &amp;</a></td></tr>
				</table>
				<h2>Login with SAML 2.0</h2>
				<div class="alert alert-danger" role="alert">Bad credentials</div>
				<table class="table table-striped">
				  <tr><td><a href="/saml/sso/google">Google &lt; &gt; &quot; &#39; &amp;</a></td></tr>
				</table>
				    </div>
				  </body>
				</html>""");
	}

}
