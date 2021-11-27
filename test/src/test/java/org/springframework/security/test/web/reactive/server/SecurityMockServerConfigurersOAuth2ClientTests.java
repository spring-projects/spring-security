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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.web.reactive.result.method.annotation.OAuth2AuthorizedClientArgumentResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.web.server.context.SecurityContextServerWebExchangeWebFilter;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.DispatcherHandler;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.adapter.WebHttpHandlerBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
public class SecurityMockServerConfigurersOAuth2ClientTests extends AbstractMockServerConfigurersTests {

	private OAuth2LoginController controller = new OAuth2LoginController();

	@Mock
	private ReactiveClientRegistrationRepository clientRegistrationRepository;

	@Mock
	private ServerOAuth2AuthorizedClientRepository authorizedClientRepository;

	private WebTestClient client;

	@BeforeEach
	public void setup() {
		this.client = WebTestClient.bindToController(this.controller)
				.argumentResolvers((c) -> c.addCustomResolver(new OAuth2AuthorizedClientArgumentResolver(
						this.clientRegistrationRepository, this.authorizedClientRepository)))
				.webFilter(new SecurityContextServerWebExchangeWebFilter())
				.apply(SecurityMockServerConfigurers.springSecurity()).configureClient()
				.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE).build();
	}

	@Test
	public void oauth2ClientWhenUsingDefaultsThenException() throws Exception {
		WebHttpHandlerBuilder builder = WebHttpHandlerBuilder.webHandler(new DispatcherHandler());
		assertThatIllegalArgumentException()
				.isThrownBy(() -> SecurityMockServerConfigurers.mockOAuth2Client().beforeServerCreated(builder))
				.withMessageContaining("ClientRegistration");
	}

	@Test
	public void oauth2ClientWhenUsingRegistrationIdThenProducesAuthorizedClient() throws Exception {
		this.client.mutateWith(SecurityMockServerConfigurers.mockOAuth2Client("registration-id")).get().uri("/client")
				.exchange().expectStatus().isOk();
		OAuth2AuthorizedClient client = this.controller.authorizedClient;
		assertThat(client).isNotNull();
		assertThat(client.getClientRegistration().getRegistrationId()).isEqualTo("registration-id");
		assertThat(client.getAccessToken().getTokenValue()).isEqualTo("access-token");
		assertThat(client.getRefreshToken()).isNull();
	}

	@Test
	public void oauth2ClientWhenClientRegistrationThenUses() throws Exception {
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration()
				.registrationId("registration-id").clientId("client-id").build();
		this.client.mutateWith(SecurityMockServerConfigurers.mockOAuth2Client().clientRegistration(clientRegistration))
				.get().uri("/client").exchange().expectStatus().isOk();
		OAuth2AuthorizedClient client = this.controller.authorizedClient;
		assertThat(client).isNotNull();
		assertThat(client.getClientRegistration().getRegistrationId()).isEqualTo("registration-id");
		assertThat(client.getAccessToken().getTokenValue()).isEqualTo("access-token");
		assertThat(client.getRefreshToken()).isNull();
	}

	@Test
	public void oauth2ClientWhenClientRegistrationConsumerThenUses() throws Exception {
		this.client
				.mutateWith(SecurityMockServerConfigurers.mockOAuth2Client("registration-id")
						.clientRegistration((c) -> c.clientId("client-id")))
				.get().uri("/client").exchange().expectStatus().isOk();
		OAuth2AuthorizedClient client = this.controller.authorizedClient;
		assertThat(client).isNotNull();
		assertThat(client.getClientRegistration().getRegistrationId()).isEqualTo("registration-id");
		assertThat(client.getClientRegistration().getClientId()).isEqualTo("client-id");
		assertThat(client.getAccessToken().getTokenValue()).isEqualTo("access-token");
		assertThat(client.getRefreshToken()).isNull();
	}

	@Test
	public void oauth2ClientWhenPrincipalNameThenUses() throws Exception {
		this.client
				.mutateWith(
						SecurityMockServerConfigurers.mockOAuth2Client("registration-id").principalName("test-subject"))
				.get().uri("/client").exchange().expectStatus().isOk().expectBody(String.class)
				.isEqualTo("test-subject");
	}

	@Test
	public void oauth2ClientWhenAccessTokenThenUses() throws Exception {
		OAuth2AccessToken accessToken = TestOAuth2AccessTokens.noScopes();
		this.client
				.mutateWith(SecurityMockServerConfigurers.mockOAuth2Client("registration-id").accessToken(accessToken))
				.get().uri("/client").exchange().expectStatus().isOk();
		OAuth2AuthorizedClient client = this.controller.authorizedClient;
		assertThat(client).isNotNull();
		assertThat(client.getClientRegistration().getRegistrationId()).isEqualTo("registration-id");
		assertThat(client.getAccessToken().getTokenValue()).isEqualTo("no-scopes");
		assertThat(client.getRefreshToken()).isNull();
	}

	@Test
	public void oauth2ClientWhenUsedOnceThenDoesNotAffectRemainingTests() throws Exception {
		this.client.mutateWith(SecurityMockServerConfigurers.mockOAuth2Client("registration-id")).get().uri("/client")
				.exchange().expectStatus().isOk();
		OAuth2AuthorizedClient client = this.controller.authorizedClient;
		assertThat(client).isNotNull();
		assertThat(client.getClientRegistration().getClientId()).isEqualTo("test-client");
		client = new OAuth2AuthorizedClient(TestClientRegistrations.clientRegistration().build(), "sub",
				TestOAuth2AccessTokens.noScopes());
		given(this.authorizedClientRepository.loadAuthorizedClient(eq("registration-id"), any(Authentication.class),
				any(ServerWebExchange.class))).willReturn(Mono.just(client));
		this.client.get().uri("/client").exchange().expectStatus().isOk();
		client = this.controller.authorizedClient;
		assertThat(client).isNotNull();
		assertThat(client.getClientRegistration().getClientId()).isEqualTo("client-id");
		verify(this.authorizedClientRepository).loadAuthorizedClient(eq("registration-id"), any(Authentication.class),
				any(ServerWebExchange.class));
	}

	@RestController
	static class OAuth2LoginController {

		volatile OAuth2AuthorizedClient authorizedClient;

		@GetMapping("/client")
		String authorizedClient(
				@RegisteredOAuth2AuthorizedClient("registration-id") OAuth2AuthorizedClient authorizedClient) {
			this.authorizedClient = authorizedClient;
			return authorizedClient.getPrincipalName();
		}

	}

}
