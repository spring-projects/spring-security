/*
 * Copyright 2002-2019 the original author or authors.
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
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link DefaultOAuth2AuthorizedClientProvider}.
 *
 * @author Joe Grandja
 */
public class DefaultOAuth2AuthorizedClientProviderTests {
	private ClientRegistrationRepository clientRegistrationRepository;
	private OAuth2AuthorizedClientRepository authorizedClientRepository;
	private DefaultOAuth2AuthorizedClientProvider authorizedClientProvider;
	private ClientRegistration clientRegistration;
	private OAuth2AuthorizedClient authorizedClient;
	private Authentication principal;

	@Before
	public void setup() {
		this.clientRegistrationRepository = mock(ClientRegistrationRepository.class);
		this.authorizedClientRepository = mock(OAuth2AuthorizedClientRepository.class);
		this.authorizedClientProvider = new DefaultOAuth2AuthorizedClientProvider(
				this.clientRegistrationRepository, this.authorizedClientRepository);
		this.clientRegistration = TestClientRegistrations.clientRegistration().build();
		this.authorizedClient = new OAuth2AuthorizedClient(
				this.clientRegistration, "principal", TestOAuth2AccessTokens.scopes("read", "write"));
		this.principal = new TestingAuthenticationToken("principal", "password");
	}

	@Test
	public void constructorWhenClientRegistrationRepositoryIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new DefaultOAuth2AuthorizedClientProvider(null, this.authorizedClientRepository))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("clientRegistrationRepository cannot be null");
	}

	@Test
	public void constructorWhenOAuth2AuthorizedClientRepositoryIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new DefaultOAuth2AuthorizedClientProvider(this.clientRegistrationRepository, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizedClientRepository cannot be null");
	}

	@Test
	public void authorizeWhenContextIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientProvider.authorize(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void authorizeWhenHttpServletRequestIsNullThenThrowIllegalArgumentException() {
		OAuth2AuthorizationContext authorizationContext =
				OAuth2AuthorizationContext.forClient(this.clientRegistration.getRegistrationId())
						.principal(this.principal)
						.build();
		assertThatThrownBy(() -> this.authorizedClientProvider.authorize(authorizationContext))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("The context attribute cannot be null 'javax.servlet.http.HttpServletRequest'");
	}

	@Test
	public void authorizeWhenHttpServletResponseIsNullThenThrowIllegalArgumentException() {
		OAuth2AuthorizationContext authorizationContext =
				OAuth2AuthorizationContext.forClient(this.clientRegistration.getRegistrationId())
						.principal(this.principal)
						.attribute(HttpServletRequest.class.getName(), new MockHttpServletRequest())
						.build();
		assertThatThrownBy(() -> this.authorizedClientProvider.authorize(authorizationContext))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("The context attribute cannot be null 'javax.servlet.http.HttpServletResponse'");
	}

	@Test
	public void authorizeWhenClientRegistrationNotFoundThenThrowIllegalArgumentException() {
		OAuth2AuthorizationContext authorizationContext =
				OAuth2AuthorizationContext.forClient(this.clientRegistration.getRegistrationId())
						.principal(this.principal)
						.attribute(HttpServletRequest.class.getName(), new MockHttpServletRequest())
						.attribute(HttpServletResponse.class.getName(), new MockHttpServletResponse())
						.build();
		assertThatThrownBy(() -> this.authorizedClientProvider.authorize(authorizationContext))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("Could not find ClientRegistration with id '" + this.clientRegistration.getRegistrationId() + "'");
	}

	@Test
	public void authorizeWhenAuthorizedThenReturnAuthorizedClient() {
		when(this.clientRegistrationRepository.findByRegistrationId(
				eq(this.clientRegistration.getRegistrationId()))).thenReturn(this.clientRegistration);

		when(this.authorizedClientRepository.loadAuthorizedClient(eq(this.clientRegistration.getRegistrationId()),
				eq(this.principal), any(HttpServletRequest.class))).thenReturn(this.authorizedClient);

		OAuth2AuthorizationContext authorizationContext =
				OAuth2AuthorizationContext.forClient(this.clientRegistration.getRegistrationId())
						.principal(this.principal)
						.attribute(HttpServletRequest.class.getName(), new MockHttpServletRequest())
						.attribute(HttpServletResponse.class.getName(), new MockHttpServletResponse())
						.build();
		assertThat(this.authorizedClientProvider.authorize(authorizationContext)).isSameAs(this.authorizedClient);
	}
}
