/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.oauth2.client.oidc.web.logout;

import java.io.IOException;
import java.net.URI;
import java.util.Collections;

import javax.servlet.ServletException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.oidc.user.TestOidcUsers;
import org.springframework.security.oauth2.core.user.TestOAuth2Users;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link OidcClientInitiatedLogoutSuccessHandler}
 */
@RunWith(MockitoJUnitRunner.class)
public class OidcClientInitiatedLogoutSuccessHandlerTests {

	ClientRegistration registration = TestClientRegistrations.clientRegistration()
			.providerConfigurationMetadata(Collections.singletonMap("end_session_endpoint", "https://endpoint"))
			.build();

	ClientRegistrationRepository repository = new InMemoryClientRegistrationRepository(this.registration);

	MockHttpServletRequest request;

	MockHttpServletResponse response;

	OidcClientInitiatedLogoutSuccessHandler handler;

	@Before
	public void setup() {
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
		this.handler = new OidcClientInitiatedLogoutSuccessHandler(this.repository);
	}

	@Test
	public void logoutWhenOidcRedirectUrlConfiguredThenRedirects() throws IOException, ServletException {
		OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(TestOidcUsers.create(),
				AuthorityUtils.NO_AUTHORITIES, this.registration.getRegistrationId());
		this.request.setUserPrincipal(token);
		this.handler.onLogoutSuccess(this.request, this.response, token);
		assertThat(this.response.getRedirectedUrl()).isEqualTo("https://endpoint?id_token_hint=id-token");
	}

	@Test
	public void logoutWhenNotOAuth2AuthenticationThenDefaults() throws IOException, ServletException {
		Authentication token = mock(Authentication.class);
		this.request.setUserPrincipal(token);
		this.handler.setDefaultTargetUrl("https://default");
		this.handler.onLogoutSuccess(this.request, this.response, token);
		assertThat(this.response.getRedirectedUrl()).isEqualTo("https://default");
	}

	@Test
	public void logoutWhenNotOidcUserThenDefaults() throws IOException, ServletException {
		OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(TestOAuth2Users.create(),
				AuthorityUtils.NO_AUTHORITIES, this.registration.getRegistrationId());
		this.request.setUserPrincipal(token);
		this.handler.setDefaultTargetUrl("https://default");
		this.handler.onLogoutSuccess(this.request, this.response, token);
		assertThat(this.response.getRedirectedUrl()).isEqualTo("https://default");
	}

	@Test
	public void logoutWhenClientRegistrationHasNoEndSessionEndpointThenDefaults() throws Exception {
		ClientRegistration registration = TestClientRegistrations.clientRegistration().build();
		ClientRegistrationRepository repository = new InMemoryClientRegistrationRepository(registration);
		OidcClientInitiatedLogoutSuccessHandler handler = new OidcClientInitiatedLogoutSuccessHandler(repository);
		OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(TestOidcUsers.create(),
				AuthorityUtils.NO_AUTHORITIES, registration.getRegistrationId());
		this.request.setUserPrincipal(token);
		handler.setDefaultTargetUrl("https://default");
		handler.onLogoutSuccess(this.request, this.response, token);
		assertThat(this.response.getRedirectedUrl()).isEqualTo("https://default");
	}

	@Test
	public void logoutWhenUsingPostLogoutRedirectUriThenIncludesItInRedirect() throws IOException, ServletException {
		OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(TestOidcUsers.create(),
				AuthorityUtils.NO_AUTHORITIES, this.registration.getRegistrationId());
		this.handler.setPostLogoutRedirectUri(URI.create("https://postlogout?encodedparam=value"));
		this.request.setUserPrincipal(token);
		this.handler.onLogoutSuccess(this.request, this.response, token);
		assertThat(this.response.getRedirectedUrl()).isEqualTo("https://endpoint?" + "id_token_hint=id-token&"
				+ "post_logout_redirect_uri=https://postlogout?encodedparam%3Dvalue");
	}

	@Test
	public void logoutWhenUsingPostLogoutRedirectUriTemplateThenBuildsItForRedirect()
			throws IOException, ServletException {
		OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(TestOidcUsers.create(),
				AuthorityUtils.NO_AUTHORITIES, this.registration.getRegistrationId());
		this.handler.setPostLogoutRedirectUri("{baseUrl}");
		this.request.setScheme("https");
		this.request.setServerPort(443);
		this.request.setServerName("rp.example.org");
		this.request.setUserPrincipal(token);
		this.handler.onLogoutSuccess(this.request, this.response, token);
		assertThat(this.response.getRedirectedUrl()).isEqualTo(
				"https://endpoint?" + "id_token_hint=id-token&" + "post_logout_redirect_uri=https://rp.example.org");
	}

	@Test
	public void setPostLogoutRedirectUriWhenGivenNullThenThrowsException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.handler.setPostLogoutRedirectUri((URI) null));
	}

	@Test
	public void setPostLogoutRedirectUriTemplateWhenGivenNullThenThrowsException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.handler.setPostLogoutRedirectUri((String) null));
	}

}
