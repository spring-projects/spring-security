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

import java.time.Instant;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link OidcIdTokenSubjectTokenResolver}.
 *
 * @author Bapuji Koraganti
 */
public class OidcIdTokenSubjectTokenResolverTests {

	private static final String ID_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:id_token";

	private static final String ACCESS_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:access_token";

	private static final String ID_TOKEN_VALUE = "eyJhbGciOiJSUzI1NiJ9.test-id-token";

	private JwtDecoderFactory<RegisteredClient> jwtDecoderFactory;

	private JwtDecoder jwtDecoder;

	private OidcIdTokenSubjectTokenResolver resolver;

	@BeforeEach
	@SuppressWarnings("unchecked")
	public void setUp() {
		this.jwtDecoderFactory = mock(JwtDecoderFactory.class);
		this.jwtDecoder = mock(JwtDecoder.class);
		given(this.jwtDecoderFactory.createDecoder(any(RegisteredClient.class))).willReturn(this.jwtDecoder);
		this.resolver = new OidcIdTokenSubjectTokenResolver(this.jwtDecoderFactory);
	}

	@Test
	public void constructorWhenJwtDecoderFactoryNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OidcIdTokenSubjectTokenResolver(null))
				.withMessage("jwtDecoderFactory cannot be null");
		// @formatter:on
	}

	@Test
	public void resolveWhenSubjectTokenTypeNotIdTokenThenReturnNull() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2TokenExchangeSubjectTokenContext result = this.resolver.resolve(ID_TOKEN_VALUE, ACCESS_TOKEN_TYPE_VALUE,
				registeredClient);
		assertThat(result).isNull();
		verifyNoInteractions(this.jwtDecoderFactory);
	}

	@Test
	public void resolveWhenJwtDecodingFailsThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		given(this.jwtDecoder.decode(anyString())).willThrow(new JwtException("Invalid token"));
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.resolver.resolve(ID_TOKEN_VALUE, ID_TOKEN_TYPE_VALUE, registeredClient))
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
		// @formatter:on
	}

	@Test
	public void resolveWhenSubjectClaimMissingThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		Jwt jwt = createJwt(null);
		given(this.jwtDecoder.decode(anyString())).willReturn(jwt);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.resolver.resolve(ID_TOKEN_VALUE, ID_TOKEN_TYPE_VALUE, registeredClient))
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
		// @formatter:on
	}

	@Test
	public void resolveWhenValidIdTokenThenReturnContext() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		Jwt jwt = createJwt("user@example.com");
		given(this.jwtDecoder.decode(anyString())).willReturn(jwt);

		OAuth2TokenExchangeSubjectTokenContext result = this.resolver.resolve(ID_TOKEN_VALUE, ID_TOKEN_TYPE_VALUE,
				registeredClient);

		assertThat(result).isNotNull();
		assertThat(result.getPrincipalName()).isEqualTo("user@example.com");
		assertThat(result.getPrincipal()).isNotNull();
		assertThat(result.getPrincipal().isAuthenticated()).isTrue();
		assertThat(result.getPrincipal().getName()).isEqualTo("user@example.com");
		assertThat(result.getClaims()).containsEntry("iss", "https://gitlab.com");
		assertThat(result.getScopes()).isEmpty();
	}

	private static Jwt createJwt(String subject) {
		Jwt.Builder builder = Jwt.withTokenValue(ID_TOKEN_VALUE)
			.header("alg", "RS256")
			.claim("iss", "https://gitlab.com")
			.claim("aud", "client-1")
			.issuedAt(Instant.now())
			.expiresAt(Instant.now().plusSeconds(300));
		if (subject != null) {
			builder.subject(subject);
		}
		return builder.build();
	}

}
