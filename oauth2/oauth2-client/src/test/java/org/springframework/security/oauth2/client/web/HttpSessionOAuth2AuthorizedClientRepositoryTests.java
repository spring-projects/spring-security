/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.client.web;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

import javax.servlet.http.HttpSession;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link HttpSessionOAuth2AuthorizedClientRepository}.
 *
 * @author Joe Grandja
 */
public class HttpSessionOAuth2AuthorizedClientRepositoryTests {
	private String registrationId1 = "registration-1";
	private String registrationId2 = "registration-2";
	private String principalName1 = "principalName-1";

	private ClientRegistration registration1 = ClientRegistration.withRegistrationId(this.registrationId1)
			.clientId("client-1")
			.clientSecret("secret")
			.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUriTemplate("{baseUrl}/login/oauth2/code/{registrationId}")
			.scope("user")
			.authorizationUri("https://provider.com/oauth2/authorize")
			.tokenUri("https://provider.com/oauth2/token")
			.userInfoUri("https://provider.com/oauth2/user")
			.userNameAttributeName("id")
			.clientName("client-1")
			.build();

	private ClientRegistration registration2 = ClientRegistration.withRegistrationId(this.registrationId2)
			.clientId("client-2")
			.clientSecret("secret")
			.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUriTemplate("{baseUrl}/login/oauth2/code/{registrationId}")
			.scope("openid", "profile", "email")
			.authorizationUri("https://provider.com/oauth2/authorize")
			.tokenUri("https://provider.com/oauth2/token")
			.userInfoUri("https://provider.com/oauth2/userinfo")
			.jwkSetUri("https://provider.com/oauth2/keys")
			.clientName("client-2")
			.build();

	private HttpSessionOAuth2AuthorizedClientRepository authorizedClientRepository =
			new HttpSessionOAuth2AuthorizedClientRepository();

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	@Before
	public void setup() {
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
	}

	@Test
	public void loadAuthorizedClientWhenClientRegistrationIdIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientRepository.loadAuthorizedClient(null, null, this.request))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void loadAuthorizedClientWhenPrincipalNameIsNullThenExceptionNotThrown() {
		this.authorizedClientRepository.loadAuthorizedClient(this.registrationId1, null, this.request);
	}

	@Test
	public void loadAuthorizedClientWhenRequestIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientRepository.loadAuthorizedClient(this.registrationId1, null, null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void loadAuthorizedClientWhenClientRegistrationNotFoundThenReturnNull() {
		OAuth2AuthorizedClient authorizedClient =
				this.authorizedClientRepository.loadAuthorizedClient("registration-not-found", null, this.request);
		assertThat(authorizedClient).isNull();
	}

	@Test
	public void loadAuthorizedClientWhenSavedThenReturnAuthorizedClient() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
				this.registration1, this.principalName1, mock(OAuth2AccessToken.class));
		this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, null, this.request, this.response);

		OAuth2AuthorizedClient loadedAuthorizedClient =
				this.authorizedClientRepository.loadAuthorizedClient(this.registrationId1, null, this.request);
		assertThat(loadedAuthorizedClient).isEqualTo(authorizedClient);
	}

	@Test
	public void saveAuthorizedClientWhenAuthorizedClientIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientRepository.saveAuthorizedClient(null, null, this.request, this.response))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void saveAuthorizedClientWhenAuthenticationIsNullThenExceptionNotThrown() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
				this.registration2, this.principalName1, mock(OAuth2AccessToken.class));
		this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, null, this.request, this.response);
	}

	@Test
	public void saveAuthorizedClientWhenRequestIsNullThenThrowIllegalArgumentException() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
				this.registration2, this.principalName1, mock(OAuth2AccessToken.class));
		assertThatThrownBy(() -> this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, null, null, this.response))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void saveAuthorizedClientWhenResponseIsNullThenThrowIllegalArgumentException() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
				this.registration2, this.principalName1, mock(OAuth2AccessToken.class));
		assertThatThrownBy(() -> this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, null, this.request, null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void saveAuthorizedClientWhenSavedThenSavedToSession() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
				this.registration2, this.principalName1, mock(OAuth2AccessToken.class));
		this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, null, this.request, this.response);

		HttpSession session = this.request.getSession(false);
		assertThat(session).isNotNull();

		@SuppressWarnings("unchecked")
		Map<String, OAuth2AuthorizedClient> authorizedClients = (Map<String, OAuth2AuthorizedClient>)
				session.getAttribute(HttpSessionOAuth2AuthorizedClientRepository.class.getName() + ".AUTHORIZED_CLIENTS");
		assertThat(authorizedClients).isNotEmpty();
		assertThat(authorizedClients).hasSize(1);
		assertThat(authorizedClients.values().iterator().next()).isSameAs(authorizedClient);
	}

	@Test
	public void removeAuthorizedClientWhenClientRegistrationIdIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientRepository.removeAuthorizedClient(
				null, null, this.request, this.response)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void removeAuthorizedClientWhenPrincipalNameIsNullThenExceptionNotThrown() {
		this.authorizedClientRepository.removeAuthorizedClient(this.registrationId1, null, this.request, this.response);
	}

	@Test
	public void removeAuthorizedClientWhenRequestIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientRepository.removeAuthorizedClient(
				this.registrationId1, null, null, this.response)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void removeAuthorizedClientWhenResponseIsNullThenExceptionNotThrown() {
		this.authorizedClientRepository.removeAuthorizedClient(this.registrationId1, null, this.request, null);
	}

	@Test
	public void removeAuthorizedClientWhenSavedThenRemoved() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
				this.registration2, this.principalName1, mock(OAuth2AccessToken.class));
		this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, null, this.request, this.response);
		OAuth2AuthorizedClient loadedAuthorizedClient = this.authorizedClientRepository.loadAuthorizedClient(
				this.registrationId2, null, this.request);
		assertThat(loadedAuthorizedClient).isSameAs(authorizedClient);
		this.authorizedClientRepository.removeAuthorizedClient(
				this.registrationId2, null, this.request, this.response);
		loadedAuthorizedClient = this.authorizedClientRepository.loadAuthorizedClient(
				this.registrationId2, null, this.request);
		assertThat(loadedAuthorizedClient).isNull();
	}

	@Test
	public void removeAuthorizedClientWhenSavedThenRemovedFromSession() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
				this.registration1, this.principalName1, mock(OAuth2AccessToken.class));
		this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, null, this.request, this.response);
		OAuth2AuthorizedClient loadedAuthorizedClient = this.authorizedClientRepository.loadAuthorizedClient(
				this.registrationId1, null, this.request);
		assertThat(loadedAuthorizedClient).isSameAs(authorizedClient);
		this.authorizedClientRepository.removeAuthorizedClient(
				this.registrationId1, null, this.request, this.response);

		HttpSession session = this.request.getSession(false);
		assertThat(session).isNotNull();
		assertThat(session.getAttribute(HttpSessionOAuth2AuthorizedClientRepository.class.getName() + ".AUTHORIZED_CLIENTS")).isNull();
	}
}
