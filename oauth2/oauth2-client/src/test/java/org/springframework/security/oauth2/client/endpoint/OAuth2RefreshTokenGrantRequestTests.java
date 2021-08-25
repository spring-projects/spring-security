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

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.TestOAuth2RefreshTokens;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link OAuth2RefreshTokenGrantRequest}.
 *
 * @author Joe Grandja
 */
public class OAuth2RefreshTokenGrantRequestTests {

	private ClientRegistration clientRegistration;

	private OAuth2AccessToken accessToken;

	private OAuth2RefreshToken refreshToken;

	@BeforeEach
	public void setup() {
		this.clientRegistration = TestClientRegistrations.clientRegistration().build();
		this.accessToken = TestOAuth2AccessTokens.scopes("read", "write");
		this.refreshToken = TestOAuth2RefreshTokens.refreshToken();
	}

	@Test
	public void constructorWhenClientRegistrationIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OAuth2RefreshTokenGrantRequest(null, this.accessToken, this.refreshToken))
				.withMessage("clientRegistration cannot be null");
	}

	@Test
	public void constructorWhenAccessTokenIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OAuth2RefreshTokenGrantRequest(this.clientRegistration, null, this.refreshToken))
				.withMessage("accessToken cannot be null");
	}

	@Test
	public void constructorWhenRefreshTokenIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OAuth2RefreshTokenGrantRequest(this.clientRegistration, this.accessToken, null))
				.withMessage("refreshToken cannot be null");
	}

	@Test
	public void constructorWhenValidParametersProvidedThenCreated() {
		Set<String> scopes = new HashSet<>(Arrays.asList("read", "write"));
		OAuth2RefreshTokenGrantRequest refreshTokenGrantRequest = new OAuth2RefreshTokenGrantRequest(
				this.clientRegistration, this.accessToken, this.refreshToken, scopes);
		assertThat(refreshTokenGrantRequest.getClientRegistration()).isSameAs(this.clientRegistration);
		assertThat(refreshTokenGrantRequest.getAccessToken()).isSameAs(this.accessToken);
		assertThat(refreshTokenGrantRequest.getRefreshToken()).isSameAs(this.refreshToken);
		assertThat(refreshTokenGrantRequest.getScopes()).isEqualTo(scopes);
	}

}
