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

package org.springframework.security.oauth2.server.resource.authentication;

import java.util.function.Predicate;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.TestJwts;
import org.springframework.security.oauth2.server.resource.BearerTokenErrorCodes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link JwtAuthenticationProvider}
 *
 * @author Josh Cummings
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@ExtendWith(MockitoExtension.class)
public class JwtAuthenticationProviderTests {

	@Mock
	Converter<Jwt, AbstractAuthenticationToken> jwtAuthenticationConverter;

	@Mock
	JwtDecoder jwtDecoder;

	JwtAuthenticationProvider provider;

	@BeforeEach
	public void setup() {
		this.provider = new JwtAuthenticationProvider(this.jwtDecoder);
		this.provider.setJwtAuthenticationConverter(this.jwtAuthenticationConverter);
	}

	@Test
	public void authenticateWhenJwtDecodesThenAuthenticationHasAttributesContainedInJwt() {
		BearerTokenAuthenticationToken token = this.authentication();
		Jwt jwt = TestJwts.jwt().claim("name", "value").build();
		given(this.jwtDecoder.decode("token")).willReturn(jwt);
		given(this.jwtAuthenticationConverter.convert(jwt)).willReturn(new JwtAuthenticationToken(jwt));
		JwtAuthenticationToken authentication = (JwtAuthenticationToken) this.provider.authenticate(token);
		assertThat(authentication.getTokenAttributes()).containsEntry("name", "value");
	}

	@Test
	public void authenticateWhenJwtDecodeFailsThenRespondsWithInvalidToken() {
		BearerTokenAuthenticationToken token = this.authentication();
		given(this.jwtDecoder.decode("token")).willThrow(BadJwtException.class);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(token))
				.matches(errorCode(BearerTokenErrorCodes.INVALID_TOKEN));
		// @formatter:on
	}

	@Test
	public void authenticateWhenDecoderThrowsIncompatibleErrorMessageThenWrapsWithGenericOne() {
		BearerTokenAuthenticationToken token = this.authentication();
		given(this.jwtDecoder.decode(token.getToken())).willThrow(new BadJwtException("with \"invalid\" chars"));
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(token))
				.satisfies((ex) -> assertThat(ex).hasFieldOrPropertyWithValue("error.description", "Invalid token"));
		// @formatter:on
	}

	// gh-7785
	@Test
	public void authenticateWhenDecoderFailsGenericallyThenThrowsGenericException() {
		BearerTokenAuthenticationToken token = this.authentication();
		given(this.jwtDecoder.decode(token.getToken())).willThrow(new JwtException("no jwk set"));
		// @formatter:off
		assertThatExceptionOfType(AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(token))
				.isNotInstanceOf(OAuth2AuthenticationException.class);
		// @formatter:on
	}

	@Test
	public void authenticateWhenConverterReturnsAuthenticationThenProviderPropagatesIt() {
		BearerTokenAuthenticationToken token = this.authentication();
		Jwt jwt = TestJwts.jwt().build();
		JwtAuthenticationToken authentication = new JwtAuthenticationToken(jwt);
		given(this.jwtDecoder.decode(token.getToken())).willReturn(jwt);
		given(this.jwtAuthenticationConverter.convert(jwt)).willReturn(authentication);

		assertThat(this.provider.authenticate(token)).isEqualTo(authentication);
	}

	@Test
	public void authenticateWhenConverterDoesNotSetAuthenticationDetailsThenProviderSetsItWithTokenDetails() {
		BearerTokenAuthenticationToken token = this.authentication();
		Object details = mock(Object.class);
		token.setDetails(details);
		Jwt jwt = TestJwts.jwt().build();
		JwtAuthenticationToken authentication = new JwtAuthenticationToken(jwt);
		given(this.jwtDecoder.decode(token.getToken())).willReturn(jwt);
		given(this.jwtAuthenticationConverter.convert(jwt)).willReturn(authentication);
		// @formatter:off
		assertThat(this.provider.authenticate(token))
				.isEqualTo(authentication).hasFieldOrPropertyWithValue("details",
						details);
		// @formatter:on
	}

	@Test
	public void authenticateWhenConverterSetsAuthenticationDetailsThenProviderDoesNotOverwriteIt() {
		BearerTokenAuthenticationToken token = this.authentication();
		Object details = mock(Object.class);
		token.setDetails(details);
		Jwt jwt = TestJwts.jwt().build();
		JwtAuthenticationToken authentication = new JwtAuthenticationToken(jwt);
		Object expectedDetails = "To be kept as is";
		authentication.setDetails(expectedDetails);
		given(this.jwtDecoder.decode(token.getToken())).willReturn(jwt);
		given(this.jwtAuthenticationConverter.convert(jwt)).willReturn(authentication);
		// @formatter:off
		assertThat(this.provider.authenticate(token))
				.isEqualTo(authentication).hasFieldOrPropertyWithValue("details",
						expectedDetails);
		// @formatter:on
	}

	@Test
	public void authenticateWhenConverterReturnsNullThenThrowException() {
		BearerTokenAuthenticationToken token = this.authentication();
		Jwt jwt = TestJwts.jwt().build();
		given(this.jwtDecoder.decode("token")).willReturn(jwt);
		given(this.jwtAuthenticationConverter.convert(jwt)).willReturn(null);
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.provider.authenticate(token))
				.withMessageContaining("token cannot be null");
		// @formatter:on
	}

	@Test
	public void supportsWhenBearerTokenAuthenticationTokenThenReturnsTrue() {
		assertThat(this.provider.supports(BearerTokenAuthenticationToken.class)).isTrue();
	}

	private BearerTokenAuthenticationToken authentication() {
		return new BearerTokenAuthenticationToken("token");
	}

	private Predicate<? super Throwable> errorCode(String errorCode) {
		return (failed) -> ((OAuth2AuthenticationException) failed).getError().getErrorCode() == errorCode;
	}

}
