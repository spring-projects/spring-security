/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.oauth2.client;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.when;

/**
 * @author Rob Winch
 * @since 5.1
 */
@RunWith(MockitoJUnitRunner.class)
public class InMemoryReactiveOAuth2AuthorizedClientServiceTests {
	@Mock
	private ReactiveClientRegistrationRepository clientRegistrationRepository;

	private InMemoryReactiveOAuth2AuthorizedClientService authorizedClientService;

	private String clientRegistrationId = "github";

	private String principalName = "username";

	private Authentication principal = new TestingAuthenticationToken(this.principalName, "notused");

	OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
			"token",
			Instant.now(),
			Instant.now().plus(Duration.ofDays(1)));

	private ClientRegistration clientRegistration = ClientRegistration.withRegistrationId(this.clientRegistrationId)
			.redirectUri("{baseUrl}/{action}/oauth2/code/{registrationId}")
			.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.scope("read:user")
			.authorizationUri("https://github.com/login/oauth/authorize")
			.tokenUri("https://github.com/login/oauth/access_token")
			.userInfoUri("https://api.github.com/user")
			.userNameAttributeName("id")
			.clientName("GitHub")
			.clientId("clientId")
			.clientSecret("clientSecret")
			.build();

	@Before
	public void setup() {
		this.authorizedClientService = new InMemoryReactiveOAuth2AuthorizedClientService(
				this.clientRegistrationRepository);
	}

	@Test
	public void constructorNullClientRegistrationRepositoryThenThrowsIllegalArgumentException() {
		this.clientRegistrationRepository = null;
		assertThatThrownBy(() -> new InMemoryReactiveOAuth2AuthorizedClientService(this.clientRegistrationRepository))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void loadAuthorizedClientWhenClientRegistrationIdNullThenIllegalArgumentException() {
		this.clientRegistrationId = null;
		assertThatThrownBy(() -> this.authorizedClientService.loadAuthorizedClient(this.clientRegistrationId, this.principalName))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void loadAuthorizedClientWhenClientRegistrationIdEmptyThenIllegalArgumentException() {
		this.clientRegistrationId = "";
		assertThatThrownBy(() -> this.authorizedClientService.loadAuthorizedClient(this.clientRegistrationId, this.principalName))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void loadAuthorizedClientWhenPrincipalNameNullThenIllegalArgumentException() {
		this.principalName = null;
		assertThatThrownBy(() -> this.authorizedClientService.loadAuthorizedClient(this.clientRegistrationId, this.principalName))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void loadAuthorizedClientWhenPrincipalNameEmptyThenIllegalArgumentException() {
		this.principalName = "";
		assertThatThrownBy(() -> this.authorizedClientService.loadAuthorizedClient(this.clientRegistrationId, this.principalName))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void loadAuthorizedClientWhenClientRegistrationIdNotFoundThenEmpty() {
		when(this.clientRegistrationRepository.findByRegistrationId(this.clientRegistrationId))
				.thenReturn(Mono.empty());
		StepVerifier
			.create(this.authorizedClientService.loadAuthorizedClient(this.clientRegistrationId, this.principalName))
			.verifyComplete();
	}

	@Test
	public void loadAuthorizedClientWhenClientRegistrationFoundAndNotAuthorizedClientThenEmpty() {
		when(this.clientRegistrationRepository.findByRegistrationId(this.clientRegistrationId)).thenReturn(Mono.just(this.clientRegistration));
		StepVerifier
				.create(this.authorizedClientService.loadAuthorizedClient(this.clientRegistrationId, this.principalName))
				.verifyComplete();
	}

	@Test
	public void loadAuthorizedClientWhenClientRegistrationFoundThenFound() {
		when(this.clientRegistrationRepository.findByRegistrationId(this.clientRegistrationId)).thenReturn(Mono.just(this.clientRegistration));
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration, this.principalName, this.accessToken);
		Mono<OAuth2AuthorizedClient> saveAndLoad = this.authorizedClientService.saveAuthorizedClient(authorizedClient, this.principal)
				.then(this.authorizedClientService.loadAuthorizedClient(this.clientRegistrationId, this.principalName));

		StepVerifier.create(saveAndLoad)
			.expectNext(authorizedClient)
			.verifyComplete();
	}

	@Test
	public void saveAuthorizedClientWhenAuthorizedClientNullThenIllegalArgumentException() {
		OAuth2AuthorizedClient authorizedClient = null;
		assertThatThrownBy(() -> this.authorizedClientService.saveAuthorizedClient(authorizedClient, this.principal))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void saveAuthorizedClientWhenPrincipalNullThenIllegalArgumentException() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration, this.principalName, this.accessToken);
		this.principal = null;
		assertThatThrownBy(() -> this.authorizedClientService.saveAuthorizedClient(authorizedClient, this.principal))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void removeAuthorizedClientWhenClientRegistrationIdNullThenIllegalArgumentException() {
		this.clientRegistrationId = null;
		assertThatThrownBy(() -> this.authorizedClientService.loadAuthorizedClient(this.clientRegistrationId, this.principalName))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void removeAuthorizedClientWhenClientRegistrationIdEmptyThenIllegalArgumentException() {
		this.clientRegistrationId = "";
		assertThatThrownBy(() -> this.authorizedClientService.loadAuthorizedClient(this.clientRegistrationId, this.principalName))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void removeAuthorizedClientWhenPrincipalNameNullThenIllegalArgumentException() {
		this.principalName = null;
		assertThatThrownBy(() -> this.authorizedClientService.removeAuthorizedClient(this.clientRegistrationId, this.principalName))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void removeAuthorizedClientWhenPrincipalNameEmptyThenIllegalArgumentException() {
		this.principalName = "";
		assertThatThrownBy(() -> this.authorizedClientService.removeAuthorizedClient(this.clientRegistrationId, this.principalName))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void removeAuthorizedClientWhenClientIdThenNoException() {
		when(this.clientRegistrationRepository.findByRegistrationId(this.clientRegistrationId)).thenReturn(Mono.empty());
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration, this.principalName, this.accessToken);
		Mono<Void> saveAndDeleteAndLoad = this.authorizedClientService.saveAuthorizedClient(authorizedClient, this.principal)
				.then(this.authorizedClientService.removeAuthorizedClient(this.clientRegistrationId, this.principalName));

		StepVerifier.create(saveAndDeleteAndLoad)
				.verifyComplete();
	}

	@Test
	public void removeAuthorizedClientWhenClientRegistrationFoundRemovedThenNotFound() {
		when(this.clientRegistrationRepository.findByRegistrationId(this.clientRegistrationId)).thenReturn(Mono.just(this.clientRegistration));
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration, this.principalName, this.accessToken);
		Mono<OAuth2AuthorizedClient> saveAndDeleteAndLoad = this.authorizedClientService.saveAuthorizedClient(authorizedClient, this.principal)
				.then(this.authorizedClientService.removeAuthorizedClient(this.clientRegistrationId, this.principalName))
				.then(this.authorizedClientService.loadAuthorizedClient(this.clientRegistrationId, this.principalName));

		StepVerifier.create(saveAndDeleteAndLoad)
				.verifyComplete();
	}
}
