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

package org.springframework.security.test.web.reactive.server;

import java.util.Collection;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.reactive.result.method.annotation.OAuth2AuthorizedClientArgumentResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.server.context.SecurityContextServerWebExchangeWebFilter;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.oauth2.core.oidc.TestOidcIdTokens.idToken;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockOAuth2Login;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockOidcLogin;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

@RunWith(MockitoJUnitRunner.class)
public class SecurityMockServerConfigurersOidcLoginTests extends AbstractMockServerConfigurersTests {

	private OAuth2LoginController controller = new OAuth2LoginController();

	@Mock
	private ReactiveClientRegistrationRepository clientRegistrationRepository;

	@Mock
	private ServerOAuth2AuthorizedClientRepository authorizedClientRepository;

	private WebTestClient client;

	@Before
	public void setup() {
		this.client = WebTestClient.bindToController(this.controller)
				.argumentResolvers(c -> c.addCustomResolver(new OAuth2AuthorizedClientArgumentResolver(
						this.clientRegistrationRepository, this.authorizedClientRepository)))
				.webFilter(new SecurityContextServerWebExchangeWebFilter()).apply(springSecurity()).configureClient()
				.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE).build();
	}

	@Test
	public void oidcLoginWhenUsingDefaultsThenProducesDefaultAuthentication() {
		this.client.mutateWith(mockOidcLogin()).get().uri("/token").exchange().expectStatus().isOk();

		OAuth2AuthenticationToken token = this.controller.token;
		assertThat(token).isNotNull();
		assertThat(token.getAuthorizedClientRegistrationId()).isEqualTo("test");
		assertThat(token.getPrincipal()).isInstanceOf(OidcUser.class);
		assertThat(token.getPrincipal().getAttributes()).containsEntry("sub", "user");
		assertThat((Collection<GrantedAuthority>) token.getPrincipal().getAuthorities())
				.contains(new SimpleGrantedAuthority("SCOPE_read"));
		assertThat(((OidcUser) token.getPrincipal()).getIdToken().getTokenValue()).isEqualTo("id-token");
	}

	@Test
	public void oidcLoginWhenUsingDefaultsThenProducesDefaultAuthorizedClient() {
		this.client.mutateWith(mockOidcLogin()).get().uri("/client").exchange().expectStatus().isOk();

		OAuth2AuthorizedClient client = this.controller.authorizedClient;
		assertThat(client).isNotNull();
		assertThat(client.getClientRegistration().getRegistrationId()).isEqualTo("test");
		assertThat(client.getAccessToken().getTokenValue()).isEqualTo("access-token");
		assertThat(client.getRefreshToken()).isNull();
	}

	@Test
	public void oidcLoginWhenAuthoritiesSpecifiedThenGrantsAccess() {
		this.client.mutateWith(mockOidcLogin().authorities(new SimpleGrantedAuthority("SCOPE_admin"))).get()
				.uri("/token").exchange().expectStatus().isOk();

		OAuth2AuthenticationToken token = this.controller.token;
		assertThat((Collection<GrantedAuthority>) token.getPrincipal().getAuthorities())
				.contains(new SimpleGrantedAuthority("SCOPE_admin"));
	}

	@Test
	public void oidcLoginWhenIdTokenSpecifiedThenUserHasClaims() {
		this.client.mutateWith(mockOidcLogin().idToken(i -> i.issuer("https://idp.example.org"))).get().uri("/token")
				.exchange().expectStatus().isOk();

		OAuth2AuthenticationToken token = this.controller.token;
		assertThat(token.getPrincipal().getAttributes()).containsEntry("iss", "https://idp.example.org");
	}

	@Test
	public void oidcLoginWhenUserInfoSpecifiedThenUserHasClaims() throws Exception {
		this.client.mutateWith(mockOidcLogin().userInfoToken(u -> u.email("email@email"))).get().uri("/token")
				.exchange().expectStatus().isOk();

		OAuth2AuthenticationToken token = this.controller.token;
		assertThat(token.getPrincipal().getAttributes()).containsEntry("email", "email@email");
	}

	@Test
	public void oidcUserWhenNameSpecifiedThenUserHasName() throws Exception {
		OidcUser oidcUser = new DefaultOidcUser(AuthorityUtils.commaSeparatedStringToAuthorityList("SCOPE_read"),
				OidcIdToken.withTokenValue("id-token").claim("custom-attribute", "test-subject").build(),
				"custom-attribute");

		this.client.mutateWith(mockOAuth2Login().oauth2User(oidcUser)).get().uri("/token").exchange().expectStatus()
				.isOk();

		OAuth2AuthenticationToken token = this.controller.token;
		assertThat(token.getPrincipal().getName()).isEqualTo("test-subject");

		this.client.mutateWith(mockOAuth2Login().oauth2User(oidcUser)).get().uri("/client").exchange().expectStatus()
				.isOk();

		OAuth2AuthorizedClient client = this.controller.authorizedClient;
		assertThat(client.getPrincipalName()).isEqualTo("test-subject");
	}

	// gh-7794
	@Test
	public void oidcLoginWhenOidcUserSpecifiedThenLastCalledTakesPrecedence() throws Exception {
		OidcUser oidcUser = new DefaultOidcUser(AuthorityUtils.createAuthorityList("SCOPE_read"), idToken().build());

		this.client.mutateWith(mockOidcLogin().idToken(i -> i.subject("foo")).oidcUser(oidcUser)).get().uri("/token")
				.exchange().expectStatus().isOk();

		OAuth2AuthenticationToken token = this.controller.token;
		assertThat(token.getPrincipal().getAttributes()).containsEntry("sub", "subject");

		this.client.mutateWith(mockOidcLogin().oidcUser(oidcUser).idToken(i -> i.subject("bar"))).get().uri("/token")
				.exchange().expectStatus().isOk();

		token = this.controller.token;
		assertThat(token.getPrincipal().getAttributes()).containsEntry("sub", "bar");
	}

	@RestController
	static class OAuth2LoginController {

		volatile OAuth2AuthenticationToken token;

		volatile OAuth2AuthorizedClient authorizedClient;

		@GetMapping("/token")
		OAuth2AuthenticationToken token(OAuth2AuthenticationToken token) {
			this.token = token;
			return token;
		}

		@GetMapping("/client")
		String authorizedClient(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient) {
			this.authorizedClient = authorizedClient;
			return authorizedClient.getPrincipalName();
		}

	}

}
