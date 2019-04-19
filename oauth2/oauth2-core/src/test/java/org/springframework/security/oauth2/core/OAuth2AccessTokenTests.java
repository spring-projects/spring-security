/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.oauth2.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.byLessThan;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.junit.Test;
import org.springframework.util.SerializationUtils;

/**
 * Tests for {@link OAuth2AccessToken}.
 *
 * @author Joe Grandja
 */
public class OAuth2AccessTokenTests {
	private static final OAuth2AccessToken.TokenType TOKEN_TYPE = OAuth2AccessToken.TokenType.BEARER;
	private static final String TOKEN_VALUE = "access-token";
	private static final Instant ISSUED_AT = Instant.now();
	private static final Instant EXPIRES_AT = Instant.from(ISSUED_AT).plusSeconds(60);
	private static final Set<String> SCOPES = new LinkedHashSet<>(Arrays.asList("scope1", "scope2"));
	
	static Map<String, Object> attributes(final Instant iat, final Instant exp){
		final Map<String, Object> attributes = new HashMap<>();
		attributes.put("iat", iat.getEpochSecond());
		attributes.put("exp", exp.getEpochSecond());
		return attributes;
	}
	
	static Map<String, Object> attributes(){
		return attributes(ISSUED_AT, EXPIRES_AT);
	}

	@Test
	public void tokenTypeGetValueWhenTokenTypeBearerThenReturnBearer() {
		assertThat(OAuth2AccessToken.TokenType.BEARER.getValue()).isEqualTo("Bearer");
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenTokenTypeIsNullThenThrowIllegalArgumentException() {
		new OAuth2AccessToken(null, TOKEN_VALUE, attributes());
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenTokenValueIsNullThenThrowIllegalArgumentException() {
		new OAuth2AccessToken(TOKEN_TYPE, null, attributes());
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenIssuedAtAfterExpiresAtThenThrowIllegalArgumentException() {
		new OAuth2AccessToken(TOKEN_TYPE, TOKEN_VALUE, attributes(Instant.from(EXPIRES_AT).plusSeconds(1), EXPIRES_AT));
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenExpiresAtBeforeIssuedAtThenThrowIllegalArgumentException() {
		new OAuth2AccessToken(TOKEN_TYPE, TOKEN_VALUE, attributes(ISSUED_AT, Instant.from(ISSUED_AT).minusSeconds(1)));
	}

	@Test
	public void constructorWhenAllParametersProvidedAndValidThenCreated() {
		OAuth2AccessToken accessToken = new OAuth2AccessToken(
			TOKEN_TYPE, TOKEN_VALUE, attributes(), SCOPES);

		assertThat(accessToken.getTokenType()).isEqualTo(TOKEN_TYPE);
		assertThat(accessToken.getTokenValue()).isEqualTo(TOKEN_VALUE);
		assertThat(accessToken.getIssuedAt()).isCloseTo(ISSUED_AT, byLessThan(1, ChronoUnit.SECONDS));
		assertThat(accessToken.getExpiresAt()).isCloseTo(EXPIRES_AT, byLessThan(1, ChronoUnit.SECONDS));
		assertThat(accessToken.getScopes()).isEqualTo(SCOPES);
	}

	// gh-5492
	@Test
	public void constructorWhenCreatedThenIsSerializableAndDeserializable() {
		OAuth2AccessToken accessToken = new OAuth2AccessToken(
				TOKEN_TYPE, TOKEN_VALUE, attributes(), SCOPES);
		byte[] serialized = SerializationUtils.serialize(accessToken);
		accessToken = (OAuth2AccessToken) SerializationUtils.deserialize(serialized);

		assertThat(serialized).isNotNull();
		assertThat(accessToken.getTokenType()).isEqualTo(TOKEN_TYPE);
		assertThat(accessToken.getTokenValue()).isEqualTo(TOKEN_VALUE);
		assertThat(accessToken.getIssuedAt()).isCloseTo(ISSUED_AT, byLessThan(1, ChronoUnit.SECONDS));
		assertThat(accessToken.getExpiresAt()).isCloseTo(EXPIRES_AT, byLessThan(1, ChronoUnit.SECONDS));
		assertThat(accessToken.getScopes()).isEqualTo(SCOPES);
	}
}
