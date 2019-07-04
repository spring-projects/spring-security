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

import org.junit.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link DelegatingOAuth2AuthorizedClientProvider}.
 *
 * @author Joe Grandja
 */
public class DelegatingOAuth2AuthorizedClientProviderTests {

	@Test
	public void constructorWhenProvidersIsEmptyThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new DelegatingOAuth2AuthorizedClientProvider(new OAuth2AuthorizedClientProvider[0]))
				.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new DelegatingOAuth2AuthorizedClientProvider(Collections.emptyList()))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void authorizeWhenContextIsNullThenThrowIllegalArgumentException() {
		DelegatingOAuth2AuthorizedClientProvider delegate = new DelegatingOAuth2AuthorizedClientProvider(
				mock(OAuth2AuthorizedClientProvider.class));
		assertThatThrownBy(() -> delegate.authorize(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("context cannot be null");
	}

	@Test
	public void authorizeWhenProviderCanAuthorizeThenReturnAuthorizedClient() {
		Authentication principal = new TestingAuthenticationToken("principal", "password");
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration().build();
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
				clientRegistration, principal.getName(), TestOAuth2AccessTokens.noScopes());

		OAuth2AuthorizedClientProvider authorizedClientProvider = mock(OAuth2AuthorizedClientProvider.class);
		when(authorizedClientProvider.authorize(any())).thenReturn(authorizedClient);

		DelegatingOAuth2AuthorizedClientProvider delegate = new DelegatingOAuth2AuthorizedClientProvider(
				mock(OAuth2AuthorizedClientProvider.class), mock(OAuth2AuthorizedClientProvider.class), authorizedClientProvider);
		OAuth2AuthorizationContext context = OAuth2AuthorizationContext.forClient(clientRegistration)
				.principal(principal)
				.build();
		OAuth2AuthorizedClient reauthorizedClient = delegate.authorize(context);
		assertThat(reauthorizedClient).isSameAs(authorizedClient);
	}

	@Test
	public void authorizeWhenProviderCantAuthorizeThenReturnNull() {
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration().build();
		OAuth2AuthorizationContext context = OAuth2AuthorizationContext.forClient(clientRegistration)
				.principal(new TestingAuthenticationToken("principal", "password"))
				.build();

		DelegatingOAuth2AuthorizedClientProvider delegate = new DelegatingOAuth2AuthorizedClientProvider(
				mock(OAuth2AuthorizedClientProvider.class), mock(OAuth2AuthorizedClientProvider.class));
		assertThat(delegate.authorize(context)).isNull();
	}
}
