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
package org.springframework.security.oauth2.client.web.server;

import org.junit.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.web.server.WebSessionServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.web.server.WebSession;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.mock;

/**
 * @author Rob Winch
 * @since 5.1
 */
public class WebSessionServerOAuth2AuthorizedClientRepositoryTests {
	private WebSessionServerOAuth2AuthorizedClientRepository authorizedClientRepository =
			new WebSessionServerOAuth2AuthorizedClientRepository();

	private MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/"));

	private ClientRegistration registration1 = TestClientRegistrations.clientRegistration().build();

	private ClientRegistration registration2 = TestClientRegistrations.clientRegistration2().build();

	private String registrationId1 = this.registration1.getRegistrationId();
	private String registrationId2 = this.registration2.getRegistrationId();
	private String principalName1 = "principalName-1";


	@Test
	public void loadAuthorizedClientWhenClientRegistrationIdIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientRepository.loadAuthorizedClient(null, null, this.exchange).block())
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void loadAuthorizedClientWhenPrincipalNameIsNullThenExceptionNotThrown() {
		this.authorizedClientRepository.loadAuthorizedClient(this.registrationId1, null, this.exchange).block();
	}

	@Test
	public void loadAuthorizedClientWhenRequestIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientRepository.loadAuthorizedClient(this.registrationId1, null, null).block())
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void loadAuthorizedClientWhenClientRegistrationNotFoundThenReturnNull() {
		OAuth2AuthorizedClient authorizedClient =
				this.authorizedClientRepository.loadAuthorizedClient("registration-not-found", null, this.exchange).block();
		assertThat(authorizedClient).isNull();
	}

	@Test
	public void loadAuthorizedClientWhenSavedThenReturnAuthorizedClient() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
				this.registration1, this.principalName1, mock(OAuth2AccessToken.class));
		this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, null, this.exchange).block();

		OAuth2AuthorizedClient loadedAuthorizedClient =
				this.authorizedClientRepository.loadAuthorizedClient(this.registrationId1, null, this.exchange).block();
		assertThat(loadedAuthorizedClient).isEqualTo(authorizedClient);
	}

	@Test
	public void saveAuthorizedClientWhenAuthorizedClientIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientRepository.saveAuthorizedClient(null, null, this.exchange).block())
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void saveAuthorizedClientWhenAuthenticationIsNullThenExceptionNotThrown() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
				this.registration2, this.principalName1, mock(OAuth2AccessToken.class));
		this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, null, this.exchange).block();
	}

	@Test
	public void saveAuthorizedClientWhenRequestIsNullThenThrowIllegalArgumentException() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
				this.registration2, this.principalName1, mock(OAuth2AccessToken.class));
		assertThatThrownBy(() -> this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, null, null).block())
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void saveAuthorizedClientWhenSavedThenSavedToSession() {
		OAuth2AuthorizedClient expected = new OAuth2AuthorizedClient(
				this.registration2, this.principalName1, mock(OAuth2AccessToken.class));
		this.authorizedClientRepository.saveAuthorizedClient(expected, null, this.exchange).block();

		OAuth2AuthorizedClient result = this.authorizedClientRepository
				.loadAuthorizedClient(this.registrationId2, null, this.exchange).block();

		assertThat(result).isEqualTo(expected);
	}

	@Test
	public void removeAuthorizedClientWhenClientRegistrationIdIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientRepository.removeAuthorizedClient(
				null, null, this.exchange)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void removeAuthorizedClientWhenPrincipalNameIsNullThenExceptionNotThrown() {
		this.authorizedClientRepository.removeAuthorizedClient(this.registrationId1, null, this.exchange);
	}

	@Test
	public void removeAuthorizedClientWhenRequestIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientRepository.removeAuthorizedClient(
				this.registrationId1, null, null)).isInstanceOf(IllegalArgumentException.class);
	}


	@Test
	public void removeAuthorizedClientWhenNotSavedThenSessionNotCreated() {
		this.authorizedClientRepository.removeAuthorizedClient(
				this.registrationId2, null, this.exchange);
		assertThat(this.exchange.getSession().block().isStarted()).isFalse();
	}

	@Test
	public void removeAuthorizedClientWhenClient1SavedAndClient2RemovedThenClient1NotRemoved() {
		OAuth2AuthorizedClient authorizedClient1 = new OAuth2AuthorizedClient(
				this.registration1, this.principalName1, mock(OAuth2AccessToken.class));
		this.authorizedClientRepository.saveAuthorizedClient(authorizedClient1, null, this.exchange).block();

		// Remove registrationId2 (never added so is not removed either)
		this.authorizedClientRepository.removeAuthorizedClient(
				this.registrationId2, null, this.exchange);

		OAuth2AuthorizedClient loadedAuthorizedClient1 = this.authorizedClientRepository.loadAuthorizedClient(
				this.registrationId1, null, this.exchange).block();
		assertThat(loadedAuthorizedClient1).isNotNull();
		assertThat(loadedAuthorizedClient1).isSameAs(authorizedClient1);
	}

	@Test
	public void removeAuthorizedClientWhenSavedThenRemoved() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
				this.registration2, this.principalName1, mock(OAuth2AccessToken.class));
		this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, null, this.exchange).block();
		OAuth2AuthorizedClient loadedAuthorizedClient = this.authorizedClientRepository.loadAuthorizedClient(
				this.registrationId2, null, this.exchange).block();
		assertThat(loadedAuthorizedClient).isSameAs(authorizedClient);
		this.authorizedClientRepository.removeAuthorizedClient(
				this.registrationId2, null, this.exchange).block();
		loadedAuthorizedClient = this.authorizedClientRepository.loadAuthorizedClient(
				this.registrationId2, null, this.exchange).block();
		assertThat(loadedAuthorizedClient).isNull();
	}

	@Test
	public void removeAuthorizedClientWhenSavedThenRemovedFromSession() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
				this.registration1, this.principalName1, mock(OAuth2AccessToken.class));
		this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, null, this.exchange).block();
		OAuth2AuthorizedClient loadedAuthorizedClient = this.authorizedClientRepository.loadAuthorizedClient(
				this.registrationId1, null, this.exchange).block();
		assertThat(loadedAuthorizedClient).isSameAs(authorizedClient);
		this.authorizedClientRepository.removeAuthorizedClient(
				this.registrationId1, null, this.exchange).block();

		WebSession session = this.exchange.getSession().block();
		assertThat(session).isNotNull();
		assertThat(session.getAttributes()).isEmpty();
	}

	@Test
	public void removeAuthorizedClientWhenClient1Client2SavedAndClient1RemovedThenClient2NotRemoved() {
		OAuth2AuthorizedClient authorizedClient1 = new OAuth2AuthorizedClient(
				this.registration1, this.principalName1, mock(OAuth2AccessToken.class));
		this.authorizedClientRepository.saveAuthorizedClient(authorizedClient1, null, this.exchange).block();

		OAuth2AuthorizedClient authorizedClient2 = new OAuth2AuthorizedClient(
				this.registration2, this.principalName1, mock(OAuth2AccessToken.class));
		this.authorizedClientRepository.saveAuthorizedClient(authorizedClient2, null, this.exchange).block();

		this.authorizedClientRepository.removeAuthorizedClient(
				this.registrationId1, null, this.exchange).block();

		OAuth2AuthorizedClient loadedAuthorizedClient2 = this.authorizedClientRepository.loadAuthorizedClient(
				this.registrationId2, null, this.exchange).block();
		assertThat(loadedAuthorizedClient2).isNotNull();
		assertThat(loadedAuthorizedClient2).isSameAs(authorizedClient2);
	}
}
