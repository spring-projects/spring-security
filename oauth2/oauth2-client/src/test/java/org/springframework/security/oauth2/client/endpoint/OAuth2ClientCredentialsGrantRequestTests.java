/*
 * Copyright 2002-2022 the original author or authors.
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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link OAuth2ClientCredentialsGrantRequest}.
 *
 * @author Joe Grandja
 */
public class OAuth2ClientCredentialsGrantRequestTests {

	private ClientRegistration clientRegistration;

	@BeforeEach
	public void setup() {
		// @formatter:off
		this.clientRegistration = ClientRegistration.withRegistrationId("registration-1")
				.clientId("client-1")
				.clientSecret("secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.scope("read", "write")
				.tokenUri("https://provider.com/oauth2/token")
				.build();
		// @formatter:on
	}

	@Test
	public void constructorWhenClientRegistrationIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new OAuth2ClientCredentialsGrantRequest(null));
	}

	@Test
	public void constructorWhenValidParametersProvidedThenCreated() {
		OAuth2ClientCredentialsGrantRequest clientCredentialsGrantRequest = new OAuth2ClientCredentialsGrantRequest(
				this.clientRegistration);
		assertThat(clientCredentialsGrantRequest.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(clientCredentialsGrantRequest.getGrantType()).isEqualTo(AuthorizationGrantType.CLIENT_CREDENTIALS);
	}

}
