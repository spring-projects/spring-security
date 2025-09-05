/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.oauth2.server.authorization.authentication;

import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link JwtClientAssertionDecoderFactory}.
 *
 * @author Joe Grandja
 */
public class JwtClientAssertionDecoderFactoryTests {

	private JwtClientAssertionDecoderFactory jwtDecoderFactory = new JwtClientAssertionDecoderFactory();

	@Test
	public void setJwtValidatorFactoryWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.jwtDecoderFactory.setJwtValidatorFactory(null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("jwtValidatorFactory cannot be null");
	}

	@Test
	public void createDecoderWhenMissingJwkSetUrlThenThrowOAuth2AuthenticationException() {
		// @formatter:off
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
				.clientSettings(
						ClientSettings.builder()
								.tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.RS256)
								.build()
				)
				.build();
		// @formatter:on

		assertThatThrownBy(() -> this.jwtDecoderFactory.createDecoder(registeredClient))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
				assertThat(error.getDescription()).isEqualTo("Failed to find a Signature Verifier for Client: '"
						+ registeredClient.getId() + "'. Check to ensure you have configured the JWK Set URL.");
			});
	}

	@Test
	public void createDecoderWhenMissingClientSecretThenThrowOAuth2AuthenticationException() {
		// @formatter:off
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientSecret(null)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
				.clientSettings(
						ClientSettings.builder()
								.tokenEndpointAuthenticationSigningAlgorithm(MacAlgorithm.HS256)
								.build()
				)
				.build();
		// @formatter:on

		assertThatThrownBy(() -> this.jwtDecoderFactory.createDecoder(registeredClient))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
				assertThat(error.getDescription()).isEqualTo("Failed to find a Signature Verifier for Client: '"
						+ registeredClient.getId() + "'. Check to ensure you have configured the client secret.");
			});
	}

	@Test
	public void createDecoderWhenMissingSigningAlgorithmThenThrowOAuth2AuthenticationException() {
		// @formatter:off
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
				.build();
		// @formatter:on

		assertThatThrownBy(() -> this.jwtDecoderFactory.createDecoder(registeredClient))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
				assertThat(error.getDescription())
					.isEqualTo("Failed to find a Signature Verifier for Client: '" + registeredClient.getId()
							+ "'. Check to ensure you have configured a valid JWS Algorithm: 'null'.");
			});
	}

}
