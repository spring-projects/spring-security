/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.oauth2.core.endpoint;

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link DefaultOAuth2AccessTokenResponseMapConverter}.
 *
 * @author Steve Riesenberg
 */
public class DefaultOAuth2AccessTokenResponseMapConverterTests {

	private Converter<OAuth2AccessTokenResponse, Map<String, Object>> messageConverter;

	@BeforeEach
	public void setup() {
		this.messageConverter = new DefaultOAuth2AccessTokenResponseMapConverter();
	}

	@Test
	public void shouldConvertFull() {
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put("custom_parameter_1", "custom-value-1");
		additionalParameters.put("custom_parameter_2", "custom-value-2");
		Set<String> scopes = new HashSet<>();
		scopes.add("read");
		scopes.add("write");
		// @formatter:off
		OAuth2AccessTokenResponse build = OAuth2AccessTokenResponse.withToken("access-token-value-1234")
				.expiresIn(3699)
				.additionalParameters(additionalParameters)
				.refreshToken("refresh-token-value-1234")
				.scopes(scopes)
				.tokenType(OAuth2AccessToken.TokenType.BEARER)
				.build();
		// @formatter:on
		Map<String, Object> result = this.messageConverter.convert(build);
		assertThat(result).hasSize(7);
		assertThat(result).containsEntry("access_token", "access-token-value-1234");
		assertThat(result).containsEntry("refresh_token", "refresh-token-value-1234");
		assertThat(result).containsEntry("scope", "read write");
		assertThat(result).containsEntry("token_type", "Bearer");
		assertThat(result.get("expires_in")).isNotNull();
		assertThat(result).containsEntry("custom_parameter_1", "custom-value-1");
		assertThat(result).containsEntry("custom_parameter_2", "custom-value-2");
	}

	@Test
	public void shouldConvertMinimal() {
		// @formatter:off
		OAuth2AccessTokenResponse build = OAuth2AccessTokenResponse.withToken("access-token-value-1234")
				.tokenType(OAuth2AccessToken.TokenType.BEARER)
				.build();
		// @formatter:on
		Map<String, Object> result = this.messageConverter.convert(build);
		assertThat(result).hasSize(3);
		assertThat(result).containsEntry("access_token", "access-token-value-1234");
		assertThat(result).containsEntry("token_type", "Bearer");
		assertThat(result.get("expires_in")).isNotNull();
	}

	// gh-9685
	@Test
	public void shouldConvertWithObjectAdditionalParameter() {
		Map<String, Object> nestedObject = new LinkedHashMap<>();
		nestedObject.put("a", "first value");
		nestedObject.put("b", "second value");
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put("custom_parameter_1", nestedObject);
		additionalParameters.put("custom_parameter_2", "custom-value-2");
		Set<String> scopes = new HashSet<>();
		scopes.add("read");
		scopes.add("write");
		// @formatter:off
		OAuth2AccessTokenResponse build = OAuth2AccessTokenResponse.withToken("access-token-value-1234")
				.expiresIn(3699)
				.additionalParameters(additionalParameters)
				.refreshToken("refresh-token-value-1234")
				.scopes(scopes)
				.tokenType(OAuth2AccessToken.TokenType.BEARER)
				.build();
		// @formatter:on
		Map<String, Object> result = this.messageConverter.convert(build);
		assertThat(result).hasSize(7);
		assertThat(result).containsEntry("access_token", "access-token-value-1234");
		assertThat(result).containsEntry("refresh_token", "refresh-token-value-1234");
		assertThat(result).containsEntry("scope", "read write");
		assertThat(result).containsEntry("token_type", "Bearer");
		assertThat(result.get("expires_in")).isNotNull();
		assertThat(result).containsEntry("custom_parameter_1", nestedObject);
		assertThat(result).containsEntry("custom_parameter_2", "custom-value-2");
	}

}
