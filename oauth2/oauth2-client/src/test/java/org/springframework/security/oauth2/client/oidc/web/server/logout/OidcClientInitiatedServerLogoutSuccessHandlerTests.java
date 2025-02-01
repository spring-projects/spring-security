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

package org.springframework.security.oauth2.client.oidc.web.server.logout;

import java.io.IOException;
import java.net.URI;
import java.util.Collections;
import java.util.Objects;

import jakarta.servlet.ServletException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link OidcClientInitiatedServerLogoutSuccessHandler}
 */
public class OidcClientInitiatedServerLogoutSuccessHandlerTests {

	// @formatter:off
	ClientRegistration registration = TestClientRegistrations
			.clientRegistration()
			.providerConfigurationMetadata(Collections.singletonMap("end_session_endpoint", "https://endpoint"))
			.build();
	// @formatter:on

	ReactiveClientRegistrationRepository repository = new InMemoryReactiveClientRegistrationRepository(
			this.registration);

	ServerWebExchange exchange;

	WebFilterChain chain;

	OidcClientInitiatedServerLogoutSuccessHandler handler;

	@BeforeEach
	public void setup() {
		this.exchange = mock(ServerWebExchange.class);
		given(this.exchange.getResponse()).willReturn(new MockServerHttpResponse());
		given(this.exchange.getRequest()).willReturn(MockServerHttpRequest.get("/").build());
		this.chain = mock(WebFilterChain.class);
		this.handler = new OidcClientInitiatedServerLogoutSuccessHandler(this.repository);
	}

	@Test
	public void logoutWhenOidcRedirectUrlConfiguredThenRedirects() {
		OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(TestOidcUsers.create(),
				AuthorityUtils.NO_AUTHORITIES, this.registration.getRegistrationId());
		given(this.exchange.getPrincipal()).willReturn(Mono.just(token));
		WebFilterExchange f = new WebFilterExchange(this.exchange, this.chain);
		this.handler.onLogoutSuccess(f, token).block();
		assertThat(redirectedUrl(this.exchange)).isEqualTo("https://endpoint?id_token_hint=id-token");
	}

	@Test
	public void logoutWhenNotOAuth2AuthenticationThenDefaults() {
		Authentication token = mock(Authentication.class);
		given(this.exchange.getPrincipal()).willReturn(Mono.just(token));
		WebFilterExchange f = new WebFilterExchange(this.exchange, this.chain);
		this.handler.setLogoutSuccessUrl(URI.create("https://default"));
		this.handler.onLogoutSuccess(f, token).block();
		assertThat(redirectedUrl(this.exchange)).isEqualTo("https://default");
	}

	@Test
	public void logoutWhenNotOidcUserThenDefaults() {
		OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(TestOAuth2Users.create(),
				AuthorityUtils.NO_AUTHORITIES, this.registration.getRegistrationId());
		given(this.exchange.getPrincipal()).willReturn(Mono.just(token));
		WebFilterExchange f = new WebFilterExchange(this.exchange, this.chain);
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
		given(this.exchange.getPrincipal()).willReturn(Mono.just(token));
		WebFilterExchange f = new WebFilterExchange(this.exchange, this.chain);
		handler.setLogoutSuccessUrl(URI.create("https://default"));
		handler.onLogoutSuccess(f, token).block();
		assertThat(redirectedUrl(this.exchange)).isEqualTo("https://default");
	}

	@Test
	public void logoutWhenUsingPostLogoutBaseUrlRedirectUriTemplateThenBuildsItForRedirect()
			throws IOException, ServletException {
		OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(TestOidcUsers.create(),
				AuthorityUtils.NO_AUTHORITIES, this.registration.getRegistrationId());
		given(this.exchange.getPrincipal()).willReturn(Mono.just(token));
		MockServerHttpRequest request = MockServerHttpRequest.get("https://rp.example.org/").build();
		given(this.exchange.getRequest()).willReturn(request);
		WebFilterExchange f = new WebFilterExchange(this.exchange, this.chain);
		this.handler.setPostLogoutRedirectUri("{baseUrl}");
		this.handler.onLogoutSuccess(f, token).block();
		assertThat(redirectedUrl(this.exchange)).isEqualTo(
				"https://endpoint?" + "id_token_hint=id-token&" + "post_logout_redirect_uri=https://rp.example.org");
	}

	// gh-11379
	@Test
	public void logoutWhenUsingPostLogoutRedirectUriWithQueryParametersThenBuildsItForRedirect() {
		OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(TestOidcUsers.create(),
				AuthorityUtils.NO_AUTHORITIES, this.registration.getRegistrationId());
		given(this.exchange.getPrincipal()).willReturn(Mono.just(token));
		this.handler.setPostLogoutRedirectUri("https://rp.example.org/context?forwardUrl=secured%3Fparam%3Dtrue");
		WebFilterExchange f = new WebFilterExchange(this.exchange, this.chain);
		this.handler.onLogoutSuccess(f, token).block();
		assertThat(redirectedUrl(this.exchange)).isEqualTo("https://endpoint?id_token_hint=id-token&"
				+ "post_logout_redirect_uri=https://rp.example.org/context?forwardUrl%3Dsecured%253Fparam%253Dtrue");
	}

	@Test
	public void logoutWhenUsingPostLogoutRedirectUriTemplateThenBuildsItForRedirect() {
		OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(TestOidcUsers.create(),
				AuthorityUtils.NO_AUTHORITIES, this.registration.getRegistrationId());
		given(this.exchange.getPrincipal()).willReturn(Mono.just(token));
		MockServerHttpRequest request = MockServerHttpRequest.get("https://rp.example.org/").build();
		given(this.exchange.getRequest()).willReturn(request);
		WebFilterExchange f = new WebFilterExchange(this.exchange, this.chain);
		this.handler.setPostLogoutRedirectUri("{baseScheme}://{baseHost}{basePort}{basePath}");
		this.handler.onLogoutSuccess(f, token).block();
		assertThat(redirectedUrl(this.exchange)).isEqualTo(
				"https://endpoint?" + "id_token_hint=id-token&" + "post_logout_redirect_uri=https://rp.example.org");
	}

	@Test
	public void logoutWhenUsingPostLogoutRedirectUriTemplateWithOtherPortThenBuildsItForRedirect() {
		OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(TestOidcUsers.create(),
				AuthorityUtils.NO_AUTHORITIES, this.registration.getRegistrationId());
		given(this.exchange.getPrincipal()).willReturn(Mono.just(token));
		MockServerHttpRequest request = MockServerHttpRequest.get("https://rp.example.org:400").build();
		given(this.exchange.getRequest()).willReturn(request);
		WebFilterExchange f = new WebFilterExchange(this.exchange, this.chain);
		this.handler.setPostLogoutRedirectUri("{baseScheme}://{baseHost}{basePort}{basePath}");
		this.handler.onLogoutSuccess(f, token).block();
		assertThat(redirectedUrl(this.exchange)).isEqualTo("https://endpoint?" + "id_token_hint=id-token&"
				+ "post_logout_redirect_uri=https://rp.example.org:400");
	}

	@Test
	public void logoutWhenUsingPostLogoutRedirectUriTemplateThenBuildsItForRedirectExpanded()
			throws IOException, ServletException {
		OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(TestOidcUsers.create(),
				AuthorityUtils.NO_AUTHORITIES, this.registration.getRegistrationId());
		given(this.exchange.getPrincipal()).willReturn(Mono.just(token));
		MockServerHttpRequest request = MockServerHttpRequest.get("https://rp.example.org/").build();
		given(this.exchange.getRequest()).willReturn(request);
		WebFilterExchange f = new WebFilterExchange(this.exchange, this.chain);
		this.handler.setPostLogoutRedirectUri("{baseUrl}/{registrationId}");
		this.handler.onLogoutSuccess(f, token).block();
		assertThat(redirectedUrl(this.exchange)).isEqualTo(String.format(
				"https://endpoint?" + "id_token_hint=id-token&" + "post_logout_redirect_uri=https://rp.example.org/%s",
				this.registration.getRegistrationId()));
	}

	@Test
	public void setPostLogoutRedirectUriTemplateWhenGivenNullThenThrowsException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.handler.setPostLogoutRedirectUri((String) null));
	}

	@Test
	public void logoutWhenCustomRedirectUriResolverSetThenRedirects() {
		OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(TestOidcUsers.create(),
				AuthorityUtils.NO_AUTHORITIES, this.registration.getRegistrationId());
		WebFilterExchange filterExchange = new WebFilterExchange(this.exchange, this.chain);
		given(this.exchange.getRequest())
			.willReturn(MockServerHttpRequest.get("/").queryParam("location", "https://test.com").build());
		// @formatter:off
		this.handler.setRedirectUriResolver((params) -> Mono.just(
						Objects.requireNonNull(params.getServerWebExchange()
								.getRequest()
								.getQueryParams()
								.getFirst("location"))));
		// @formatter:on
		this.handler.onLogoutSuccess(filterExchange, token).block();

		assertThat(redirectedUrl(this.exchange)).isEqualTo("https://test.com");
	}

	private String redirectedUrl(ServerWebExchange exchange) {
		return exchange.getResponse().getHeaders().getFirst("Location");
	}

}
