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

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link AuthorizationCodeReactiveOAuth2AuthorizedClientProvider}.
 *
 * @author Joe Grandja
 */
public class AuthorizationCodeReactiveOAuth2AuthorizedClientProviderTests {

	private AuthorizationCodeReactiveOAuth2AuthorizedClientProvider authorizedClientProvider;

	private ClientRegistration clientRegistration;

	private OAuth2AuthorizedClient authorizedClient;

	private Authentication principal;

	@Before
	public void setup() {
		this.authorizedClientProvider = new AuthorizationCodeReactiveOAuth2AuthorizedClientProvider();
		this.clientRegistration = TestClientRegistrations.clientRegistration().build();
		this.authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration, "principal",
				TestOAuth2AccessTokens.scopes("read", "write"));
		this.principal = new TestingAuthenticationToken("principal", "password");
	}

	@Test
	public void authorizeWhenContextIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientProvider.authorize(null).block())
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void authorizeWhenNotAuthorizationCodeThenUnableToAuthorize() {
		ClientRegistration clientCredentialsClient = TestClientRegistrations.clientCredentials().build();

		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withClientRegistration(clientCredentialsClient).principal(this.principal).build();
		assertThat(this.authorizedClientProvider.authorize(authorizationContext).block()).isNull();
	}

	@Test
	public void authorizeWhenAuthorizationCodeAndAuthorizedThenNotAuthorize() {
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withAuthorizedClient(this.authorizedClient).principal(this.principal).build();
		assertThat(this.authorizedClientProvider.authorize(authorizationContext).block()).isNull();
	}

	@Test
	public void authorizeWhenAuthorizationCodeAndNotAuthorizedThenAuthorize() {
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withClientRegistration(this.clientRegistration).principal(this.principal).build();
		assertThatThrownBy(() -> this.authorizedClientProvider.authorize(authorizationContext).block())
				.isInstanceOf(ClientAuthorizationRequiredException.class);
	}

}
