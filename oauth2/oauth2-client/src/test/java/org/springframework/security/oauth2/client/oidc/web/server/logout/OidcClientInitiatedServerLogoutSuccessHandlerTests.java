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

package org.springframework.security.oauth2.client.oidc.web.server.logout;

import java.io.IOException;
import java.net.URI;
import java.util.Collections;

import javax.servlet.ServletException;

import org.junit.Before;
import org.junit.Test;
import reactor.core.publisher.Mono;

import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.oidc.user.TestOidcUsers;
import org.springframework.security.oauth2.core.user.TestOAuth2Users;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link OidcClientInitiatedServerLogoutSuccessHandler}
 */
public class OidcClientInitiatedServerLogoutSuccessHandlerTests {

	ClientRegistration registration = TestClientRegistrations.clientRegistration()
			.providerConfigurationMetadata(Collections.singletonMap("end_session_endpoint", "https://endpoint"))
			.build();

	ReactiveClientRegistrationRepository repository = new InMemoryReactiveClientRegistrationRepository(registration);

	ServerWebExchange exchange;

	WebFilterChain chain;

	OidcClientInitiatedServerLogoutSuccessHandler handler;

	@Before
	public void setup() {
		this.exchange = mock(ServerWebExchange.class);
		when(this.exchange.getResponse()).thenReturn(new MockServerHttpResponse());
		when(this.exchange.getRequest()).thenReturn(MockServerHttpRequest.get("/").build());
		this.chain = mock(WebFilterChain.class);
		this.handler = new OidcClientInitiatedServerLogoutSuccessHandler(this.repository);
	}

	@Test
	public void logoutWhenOidcRedirectUrlConfiguredThenRedirects() {
		OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(TestOidcUsers.create(),
				AuthorityUtils.NO_AUTHORITIES, this.registration.getRegistrationId());

		when(this.exchange.getPrincipal()).thenReturn(Mono.just(token));
		WebFilterExchange f = new WebFilterExchange(exchange, this.chain);
		this.handler.onLogoutSuccess(f, token).block();

		assertThat(redirectedUrl(this.exchange)).isEqualTo("https://endpoint?id_token_hint=id-token");
	}

	@Test
	public void logoutWhenNotOAuth2AuthenticationThenDefaults() {
		Authentication token = mock(Authentication.class);

		when(this.exchange.getPrincipal()).thenReturn(Mono.just(token));
		WebFilterExchange f = new WebFilterExchange(exchange, this.chain);

		this.handler.setLogoutSuccessUrl(URI.create("https://default"));
		this.handler.onLogoutSuccess(f, token).block();

		assertThat(redirectedUrl(this.exchange)).isEqualTo("https://default");
	}

	@Test
	public void logoutWhenNotOidcUserThenDefaults() {
		OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(TestOAuth2Users.create(),
				AuthorityUtils.NO_AUTHORITIES, this.registration.getRegistrationId());

		when(this.exchange.getPrincipal()).thenReturn(Mono.just(token));
		WebFilterExchange f = new WebFilterExchange(exchange, this.chain);

		this.handler.setLogoutSuccessUrl(URI.create("https://default"));
		this.handler.onLogoutSuccess(f, token).block();

		assertThat(redirectedUrl(this.exchange)).isEqualTo("https://default");
	}

	@Test
	public void logoutWhenClientRegistrationHasNoEndSessionEndpointThenDefaults() {

		ClientRegistration registration = TestClientRegistrations.clientRegistration().build();
		ReactiveClientRegistrationRepository repository = new InMemoryReactiveClientRegistrationRepository(
				registration);
		OidcClientInitiatedServerLogoutSuccessHandler handler = new OidcClientInitiatedServerLogoutSuccessHandler(
				repository);

		OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(TestOidcUsers.create(),
				AuthorityUtils.NO_AUTHORITIES, registration.getRegistrationId());

		when(this.exchange.getPrincipal()).thenReturn(Mono.just(token));
		WebFilterExchange f = new WebFilterExchange(exchange, this.chain);

		handler.setLogoutSuccessUrl(URI.create("https://default"));
		handler.onLogoutSuccess(f, token).block();

		assertThat(redirectedUrl(this.exchange)).isEqualTo("https://default");
	}

	@Test
	public void logoutWhenUsingPostLogoutRedirectUriThenIncludesItInRedirect() {

		OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(TestOidcUsers.create(),
				AuthorityUtils.NO_AUTHORITIES, this.registration.getRegistrationId());

		when(this.exchange.getPrincipal()).thenReturn(Mono.just(token));
		WebFilterExchange f = new WebFilterExchange(exchange, this.chain);

		this.handler.setPostLogoutRedirectUri(URI.create("https://postlogout?encodedparam=value"));
		this.handler.onLogoutSuccess(f, token).block();

		assertThat(redirectedUrl(this.exchange)).isEqualTo("https://endpoint?" + "id_token_hint=id-token&"
				+ "post_logout_redirect_uri=https://postlogout?encodedparam%3Dvalue");
	}

	@Test
	public void logoutWhenUsingPostLogoutRedirectUriTemplateThenBuildsItForRedirect()
			throws IOException, ServletException {

		OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(TestOidcUsers.create(),
				AuthorityUtils.NO_AUTHORITIES, this.registration.getRegistrationId());
		when(this.exchange.getPrincipal()).thenReturn(Mono.just(token));
		MockServerHttpRequest request = MockServerHttpRequest.get("https://rp.example.org/").build();
		when(this.exchange.getRequest()).thenReturn(request);
		WebFilterExchange f = new WebFilterExchange(exchange, this.chain);

		this.handler.setPostLogoutRedirectUri("{baseUrl}");
		this.handler.onLogoutSuccess(f, token).block();

		assertThat(redirectedUrl(this.exchange)).isEqualTo(
				"https://endpoint?" + "id_token_hint=id-token&" + "post_logout_redirect_uri=https://rp.example.org");
	}

	@Test
	public void setPostLogoutRedirectUriWhenGivenNullThenThrowsException() {
		assertThatThrownBy(() -> this.handler.setPostLogoutRedirectUri((URI) null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void setPostLogoutRedirectUriTemplateWhenGivenNullThenThrowsException() {
		assertThatThrownBy(() -> this.handler.setPostLogoutRedirectUri((String) null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	private String redirectedUrl(ServerWebExchange exchange) {
		return exchange.getResponse().getHeaders().getFirst("Location");
	}

}
