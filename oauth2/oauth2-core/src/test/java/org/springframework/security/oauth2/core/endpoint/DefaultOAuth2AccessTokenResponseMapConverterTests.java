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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

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
		Assertions.assertEquals(7, result.size());
		Assertions.assertEquals("access-token-value-1234", result.get("access_token"));
		Assertions.assertEquals("refresh-token-value-1234", result.get("refresh_token"));
		Assertions.assertEquals("read write", result.get("scope"));
		Assertions.assertEquals("Bearer", result.get("token_type"));
		Assertions.assertNotNull(result.get("expires_in"));
		Assertions.assertEquals("custom-value-1", result.get("custom_parameter_1"));
		Assertions.assertEquals("custom-value-2", result.get("custom_parameter_2"));
	}

	@Test
	public void shouldConvertMinimal() {
		// @formatter:off
		OAuth2AccessTokenResponse build = OAuth2AccessTokenResponse.withToken("access-token-value-1234")
				.tokenType(OAuth2AccessToken.TokenType.BEARER)
				.build();
		// @formatter:on
		Map<String, Object> result = this.messageConverter.convert(build);
		Assertions.assertEquals(3, result.size());
		Assertions.assertEquals("access-token-value-1234", result.get("access_token"));
		Assertions.assertEquals("Bearer", result.get("token_type"));
		Assertions.assertNotNull(result.get("expires_in"));
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
		Assertions.assertEquals(7, result.size());
		Assertions.assertEquals("access-token-value-1234", result.get("access_token"));
		Assertions.assertEquals("refresh-token-value-1234", result.get("refresh_token"));
		Assertions.assertEquals("read write", result.get("scope"));
		Assertions.assertEquals("Bearer", result.get("token_type"));
		Assertions.assertNotNull(result.get("expires_in"));
		Assertions.assertEquals(nestedObject, result.get("custom_parameter_1"));
		Assertions.assertEquals("custom-value-2", result.get("custom_parameter_2"));
	}

}
