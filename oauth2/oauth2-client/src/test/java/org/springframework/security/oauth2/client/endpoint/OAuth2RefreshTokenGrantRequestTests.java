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
package org.springframework.security.oauth2.client.endpoint;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.TestOAuth2RefreshTokens;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link OAuth2RefreshTokenGrantRequest}.
 *
 * @author Joe Grandja
 */
public class OAuth2RefreshTokenGrantRequestTests {
	private ClientRegistration clientRegistration;
	private Authentication principal;
	private OAuth2AuthorizedClient authorizedClient;

	@Before
	public void setup() {
		this.clientRegistration = TestClientRegistrations.clientRegistration().build();
		this.principal = new TestingAuthenticationToken("principal", "password");
		this.authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration, this.principal.getName(),
				TestOAuth2AccessTokens.scopes("read", "write"), TestOAuth2RefreshTokens.refreshToken());
	}

	@Test
	public void constructorWhenAuthorizedClientIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2RefreshTokenGrantRequest(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizedClient cannot be null");
	}

	@Test
	public void constructorWhenRefreshTokenIsNullThenThrowIllegalArgumentException() {
		this.authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration,
				this.principal.getName(), TestOAuth2AccessTokens.scopes("read", "write"));
		assertThatThrownBy(() -> new OAuth2RefreshTokenGrantRequest(this.authorizedClient))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizedClient.refreshToken cannot be null");
	}

	@Test
	public void constructorWhenValidParametersProvidedThenCreated() {
		Set<String> scopes = new HashSet<>(Arrays.asList("read", "write"));
		OAuth2RefreshTokenGrantRequest refreshTokenGrantRequest =
				new OAuth2RefreshTokenGrantRequest(this.authorizedClient, scopes);
		assertThat(refreshTokenGrantRequest.getAuthorizedClient()).isSameAs(this.authorizedClient);
		assertThat(refreshTokenGrantRequest.getScopes()).isEqualTo(scopes);
	}
}
