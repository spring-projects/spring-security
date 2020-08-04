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

package org.springframework.security.oauth2.client.web;

import java.util.Map;

import javax.servlet.http.HttpSession;

import org.junit.Before;
import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link HttpSessionOAuth2AuthorizedClientRepository}.
 *
 * @author Joe Grandja
 */
public class HttpSessionOAuth2AuthorizedClientRepositoryTests {

	private String principalName1 = "principalName-1";

	private ClientRegistration registration1 = TestClientRegistrations.clientRegistration().build();

	private ClientRegistration registration2 = TestClientRegistrations.clientRegistration2().build();

	private String registrationId1 = this.registration1.getRegistrationId();

	private String registrationId2 = this.registration2.getRegistrationId();

	private HttpSessionOAuth2AuthorizedClientRepository authorizedClientRepository = new HttpSessionOAuth2AuthorizedClientRepository();

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	@Before
	public void setup() {
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
	}

	@Test
	public void loadAuthorizedClientWhenClientRegistrationIdIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.authorizedClientRepository.loadAuthorizedClient(null, null, this.request));
	}

	@Test
	public void loadAuthorizedClientWhenPrincipalNameIsNullThenExceptionNotThrown() {
		this.authorizedClientRepository.loadAuthorizedClient(this.registrationId1, null, this.request);
	}

	@Test
	public void loadAuthorizedClientWhenRequestIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(
				() -> this.authorizedClientRepository.loadAuthorizedClient(this.registrationId1, null, null));
	}

	@Test
	public void loadAuthorizedClientWhenClientRegistrationNotFoundThenReturnNull() {
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientRepository
				.loadAuthorizedClient("registration-not-found", null, this.request);
		assertThat(authorizedClient).isNull();
	}

	@Test
	public void loadAuthorizedClientWhenSavedThenReturnAuthorizedClient() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration1, this.principalName1,
				mock(OAuth2AccessToken.class));
		this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, null, this.request, this.response);
		OAuth2AuthorizedClient loadedAuthorizedClient = this.authorizedClientRepository
				.loadAuthorizedClient(this.registrationId1, null, this.request);
		assertThat(loadedAuthorizedClient).isEqualTo(authorizedClient);
	}

	@Test
	public void saveAuthorizedClientWhenAuthorizedClientIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(
				() -> this.authorizedClientRepository.saveAuthorizedClient(null, null, this.request, this.response));
	}

	@Test
	public void saveAuthorizedClientWhenAuthenticationIsNullThenExceptionNotThrown() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration2, this.principalName1,
				mock(OAuth2AccessToken.class));
		this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, null, this.request, this.response);
	}

	@Test
	public void saveAuthorizedClientWhenRequestIsNullThenThrowIllegalArgumentException() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration2, this.principalName1,
				mock(OAuth2AccessToken.class));
		assertThatIllegalArgumentException().isThrownBy(() -> this.authorizedClientRepository
				.saveAuthorizedClient(authorizedClient, null, null, this.response));
	}

	@Test
	public void saveAuthorizedClientWhenResponseIsNullThenThrowIllegalArgumentException() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration2, this.principalName1,
				mock(OAuth2AccessToken.class));
		assertThatIllegalArgumentException().isThrownBy(
				() -> this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, null, this.request, null));
	}

	@Test
	public void saveAuthorizedClientWhenSavedThenSavedToSession() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration2, this.principalName1,
				mock(OAuth2AccessToken.class));
		this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, null, this.request, this.response);
		HttpSession session = this.request.getSession(false);
		assertThat(session).isNotNull();
		@SuppressWarnings("unchecked")
		Map<String, OAuth2AuthorizedClient> authorizedClients = (Map<String, OAuth2AuthorizedClient>) session
				.getAttribute(HttpSessionOAuth2AuthorizedClientRepository.class.getName() + ".AUTHORIZED_CLIENTS");
		assertThat(authorizedClients).isNotEmpty();
		assertThat(authorizedClients).hasSize(1);
		assertThat(authorizedClients.values().iterator().next()).isSameAs(authorizedClient);
	}

	@Test
	public void removeAuthorizedClientWhenClientRegistrationIdIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(
				() -> this.authorizedClientRepository.removeAuthorizedClient(null, null, this.request, this.response));
	}

	@Test
	public void removeAuthorizedClientWhenPrincipalNameIsNullThenExceptionNotThrown() {
		this.authorizedClientRepository.removeAuthorizedClient(this.registrationId1, null, this.request, this.response);
	}

	@Test
	public void removeAuthorizedClientWhenRequestIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.authorizedClientRepository
				.removeAuthorizedClient(this.registrationId1, null, null, this.response));
	}

	@Test
	public void removeAuthorizedClientWhenResponseIsNullThenExceptionNotThrown() {
		this.authorizedClientRepository.removeAuthorizedClient(this.registrationId1, null, this.request, null);
	}

	@Test
	public void removeAuthorizedClientWhenNotSavedThenSessionNotCreated() {
		this.authorizedClientRepository.removeAuthorizedClient(this.registrationId2, null, this.request, this.response);
		assertThat(this.request.getSession(false)).isNull();
	}

	@Test
	public void removeAuthorizedClientWhenClient1SavedAndClient2RemovedThenClient1NotRemoved() {
		OAuth2AuthorizedClient authorizedClient1 = new OAuth2AuthorizedClient(this.registration1, this.principalName1,
				mock(OAuth2AccessToken.class));
		this.authorizedClientRepository.saveAuthorizedClient(authorizedClient1, null, this.request, this.response);
		// Remove registrationId2 (never added so is not removed either)
		this.authorizedClientRepository.removeAuthorizedClient(this.registrationId2, null, this.request, this.response);
		OAuth2AuthorizedClient loadedAuthorizedClient1 = this.authorizedClientRepository
				.loadAuthorizedClient(this.registrationId1, null, this.request);
		assertThat(loadedAuthorizedClient1).isNotNull();
		assertThat(loadedAuthorizedClient1).isSameAs(authorizedClient1);
	}

	@Test
	public void removeAuthorizedClientWhenSavedThenRemoved() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration2, this.principalName1,
				mock(OAuth2AccessToken.class));
		this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, null, this.request, this.response);
		OAuth2AuthorizedClient loadedAuthorizedClient = this.authorizedClientRepository
				.loadAuthorizedClient(this.registrationId2, null, this.request);
		assertThat(loadedAuthorizedClient).isSameAs(authorizedClient);
		this.authorizedClientRepository.removeAuthorizedClient(this.registrationId2, null, this.request, this.response);
		loadedAuthorizedClient = this.authorizedClientRepository.loadAuthorizedClient(this.registrationId2, null,
				this.request);
		assertThat(loadedAuthorizedClient).isNull();
	}

	@Test
	public void removeAuthorizedClientWhenSavedThenRemovedFromSession() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration1, this.principalName1,
				mock(OAuth2AccessToken.class));
		this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, null, this.request, this.response);
		OAuth2AuthorizedClient loadedAuthorizedClient = this.authorizedClientRepository
				.loadAuthorizedClient(this.registrationId1, null, this.request);
		assertThat(loadedAuthorizedClient).isSameAs(authorizedClient);
		this.authorizedClientRepository.removeAuthorizedClient(this.registrationId1, null, this.request, this.response);
		HttpSession session = this.request.getSession(false);
		assertThat(session).isNotNull();
		assertThat(session
				.getAttribute(HttpSessionOAuth2AuthorizedClientRepository.class.getName() + ".AUTHORIZED_CLIENTS"))
						.isNull();
	}

	@Test
	public void removeAuthorizedClientWhenClient1Client2SavedAndClient1RemovedThenClient2NotRemoved() {
		OAuth2AuthorizedClient authorizedClient1 = new OAuth2AuthorizedClient(this.registration1, this.principalName1,
				mock(OAuth2AccessToken.class));
		this.authorizedClientRepository.saveAuthorizedClient(authorizedClient1, null, this.request, this.response);
		OAuth2AuthorizedClient authorizedClient2 = new OAuth2AuthorizedClient(this.registration2, this.principalName1,
				mock(OAuth2AccessToken.class));
		this.authorizedClientRepository.saveAuthorizedClient(authorizedClient2, null, this.request, this.response);
		this.authorizedClientRepository.removeAuthorizedClient(this.registrationId1, null, this.request, this.response);
		OAuth2AuthorizedClient loadedAuthorizedClient2 = this.authorizedClientRepository
				.loadAuthorizedClient(this.registrationId2, null, this.request);
		assertThat(loadedAuthorizedClient2).isNotNull();
		assertThat(loadedAuthorizedClient2).isSameAs(authorizedClient2);
	}

}
