/*
 * Copyright 2002-2024 the original author or authors.
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

import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link TokenExchangeGrantRequest}.
 *
 * @author Steve Riesenberg
 */
public class TokenExchangeGrantRequestTests {

	private final ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration()
		.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
		.build();

	private final OAuth2Token subjectToken = TestOAuth2AccessTokens.scopes("read", "write");

	private final OAuth2Token actorToken = TestOAuth2AccessTokens.noScopes();

	@Test
	public void constructorWhenClientRegistrationIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new TokenExchangeGrantRequest(null, this.subjectToken, this.actorToken))
				.withMessage("clientRegistration cannot be null");
		// @formatter:on
	}

	@Test
	public void constructorWhenSubjectTokenIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new TokenExchangeGrantRequest(this.clientRegistration, null, this.actorToken))
				.withMessage("subjectToken cannot be null");
		// @formatter:on
	}

	@Test
	public void constructorWhenActorTokenIsNullThenCreated() {
		TokenExchangeGrantRequest grantRequest = new TokenExchangeGrantRequest(this.clientRegistration,
				this.subjectToken, null);
		assertThat(grantRequest.getGrantType()).isEqualTo(AuthorizationGrantType.TOKEN_EXCHANGE);
		assertThat(grantRequest.getClientRegistration()).isSameAs(this.clientRegistration);
		assertThat(grantRequest.getSubjectToken()).isSameAs(this.subjectToken);
	}

	@Test
	public void constructorWhenClientRegistrationInvalidGrantTypeThenThrowIllegalArgumentException() {
		ClientRegistration registration = TestClientRegistrations.clientCredentials().build();
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new TokenExchangeGrantRequest(registration, this.subjectToken, this.actorToken))
				.withMessage("clientRegistration.authorizationGrantType must be AuthorizationGrantType.TOKEN_EXCHANGE");
		// @formatter:on
	}

	@Test
	public void constructorWhenValidParametersProvidedThenCreated() {
		TokenExchangeGrantRequest grantRequest = new TokenExchangeGrantRequest(this.clientRegistration,
				this.subjectToken, this.actorToken);
		assertThat(grantRequest.getGrantType()).isEqualTo(AuthorizationGrantType.TOKEN_EXCHANGE);
		assertThat(grantRequest.getClientRegistration()).isSameAs(this.clientRegistration);
		assertThat(grantRequest.getSubjectToken()).isSameAs(this.subjectToken);
	}

}
