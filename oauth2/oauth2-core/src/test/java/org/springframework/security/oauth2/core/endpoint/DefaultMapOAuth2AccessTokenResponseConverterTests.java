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

import java.time.Duration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link DefaultMapOAuth2AccessTokenResponseConverter}.
 *
 * @author Steve Riesenberg
 */
public class DefaultMapOAuth2AccessTokenResponseConverterTests {

	private Converter<Map<String, Object>, OAuth2AccessTokenResponse> messageConverter;

	@BeforeEach
	public void setup() {
		this.messageConverter = new DefaultMapOAuth2AccessTokenResponseConverter();
	}

	@Test
	public void shouldConvertFull() {
		Map<String, Object> map = new HashMap<>();
		map.put("access_token", "access-token-1234");
		map.put("token_type", "bearer");
		map.put("expires_in", "3600");
		map.put("scope", "read write");
		map.put("refresh_token", "refresh-token-1234");
		map.put("custom_parameter_1", "custom-value-1");
		map.put("custom_parameter_2", "custom-value-2");
		OAuth2AccessTokenResponse converted = this.messageConverter.convert(map);
		OAuth2AccessToken accessToken = converted.getAccessToken();
		assertThat(accessToken).isNotNull();
		assertThat(accessToken.getTokenValue()).isEqualTo("access-token-1234");
		assertThat(accessToken.getTokenType()).isEqualTo(OAuth2AccessToken.TokenType.BEARER);
		Set<String> scopes = accessToken.getScopes();
		assertThat(scopes).isNotNull();
		assertThat(scopes).hasSize(2);
		assertThat(scopes).contains("read");
		assertThat(scopes).contains("write");
		assertThat(Duration.between(accessToken.getIssuedAt(), accessToken.getExpiresAt()).getSeconds())
			.isEqualTo(3600);
		OAuth2RefreshToken refreshToken = converted.getRefreshToken();
		assertThat(refreshToken).isNotNull();
		assertThat(refreshToken.getTokenValue()).isEqualTo("refresh-token-1234");
		Map<String, Object> additionalParameters = converted.getAdditionalParameters();
		assertThat(additionalParameters).isNotNull();
		assertThat(additionalParameters).hasSize(2);
		assertThat(additionalParameters).containsEntry("custom_parameter_1", "custom-value-1");
		assertThat(additionalParameters).containsEntry("custom_parameter_2", "custom-value-2");
	}

	@Test
	public void shouldConvertMinimal() {
		Map<String, Object> map = new HashMap<>();
		map.put("access_token", "access-token-1234");
		map.put("token_type", "bearer");
		OAuth2AccessTokenResponse converted = this.messageConverter.convert(map);
		OAuth2AccessToken accessToken = converted.getAccessToken();
		assertThat(accessToken).isNotNull();
		assertThat(accessToken.getTokenValue()).isEqualTo("access-token-1234");
		assertThat(accessToken.getTokenType()).isEqualTo(OAuth2AccessToken.TokenType.BEARER);
		Set<String> scopes = accessToken.getScopes();
		assertThat(scopes).isNotNull();
		assertThat(scopes).isEmpty();
		assertThat(Duration.between(accessToken.getIssuedAt(), accessToken.getExpiresAt()).getSeconds()).isEqualTo(1);
		OAuth2RefreshToken refreshToken = converted.getRefreshToken();
		assertThat(refreshToken).isNull();
		Map<String, Object> additionalParameters = converted.getAdditionalParameters();
		assertThat(additionalParameters).isNotNull();
		assertThat(additionalParameters).isEmpty();
	}

	@Test
	public void shouldConvertWithUnsupportedExpiresIn() {
		Map<String, Object> map = new HashMap<>();
		map.put("access_token", "access-token-1234");
		map.put("token_type", "bearer");
		map.put("expires_in", "2100-01-01-abc");
		OAuth2AccessTokenResponse converted = this.messageConverter.convert(map);
		OAuth2AccessToken accessToken = converted.getAccessToken();
		assertThat(accessToken).isNotNull();
		assertThat(accessToken.getTokenValue()).isEqualTo("access-token-1234");
		assertThat(accessToken.getTokenType()).isEqualTo(OAuth2AccessToken.TokenType.BEARER);
		Set<String> scopes = accessToken.getScopes();
		assertThat(scopes).isNotNull();
		assertThat(scopes).isEmpty();
		assertThat(Duration.between(accessToken.getIssuedAt(), accessToken.getExpiresAt()).getSeconds()).isEqualTo(1);
		OAuth2RefreshToken refreshToken = converted.getRefreshToken();
		assertThat(refreshToken).isNull();
		Map<String, Object> additionalParameters = converted.getAdditionalParameters();
		assertThat(additionalParameters).isNotNull();
		assertThat(additionalParameters).isEmpty();
	}

	// gh-9685
	@Test
	public void shouldConvertWithNumericExpiresIn() {
		Map<String, Object> map = new HashMap<>();
		map.put("access_token", "access-token-1234");
		map.put("token_type", "bearer");
		map.put("expires_in", 3600);
		OAuth2AccessTokenResponse converted = this.messageConverter.convert(map);
		OAuth2AccessToken accessToken = converted.getAccessToken();
		assertThat(accessToken).isNotNull();
		assertThat(accessToken.getTokenValue()).isEqualTo("access-token-1234");
		assertThat(accessToken.getTokenType()).isEqualTo(OAuth2AccessToken.TokenType.BEARER);
		assertThat(Duration.between(accessToken.getIssuedAt(), accessToken.getExpiresAt()).getSeconds())
			.isEqualTo(3600);
	}

	// gh-9685
	@Test
	public void shouldConvertWithObjectAdditionalParameter() {
		Map<String, Object> map = new HashMap<>();
		map.put("access_token", "access-token-1234");
		map.put("token_type", "bearer");
		map.put("expires_in", "3600");
		map.put("scope", "read write");
		map.put("refresh_token", "refresh-token-1234");
		Map<String, Object> nestedObject = new LinkedHashMap<>();
		nestedObject.put("a", "first value");
		nestedObject.put("b", "second value");
		map.put("custom_parameter_1", nestedObject);
		map.put("custom_parameter_2", "custom-value-2");
		OAuth2AccessTokenResponse converted = this.messageConverter.convert(map);
		OAuth2AccessToken accessToken = converted.getAccessToken();
		assertThat(accessToken).isNotNull();
		assertThat(accessToken.getTokenValue()).isEqualTo("access-token-1234");
		assertThat(accessToken.getTokenType()).isEqualTo(OAuth2AccessToken.TokenType.BEARER);
		Set<String> scopes = accessToken.getScopes();
		assertThat(scopes).isNotNull();
		assertThat(scopes).hasSize(2);
		assertThat(scopes).contains("read");
		assertThat(scopes).contains("write");
		assertThat(Duration.between(accessToken.getIssuedAt(), accessToken.getExpiresAt()).getSeconds())
			.isEqualTo(3600);
		OAuth2RefreshToken refreshToken = converted.getRefreshToken();
		assertThat(refreshToken).isNotNull();
		assertThat(refreshToken.getTokenValue()).isEqualTo("refresh-token-1234");
		Map<String, Object> additionalParameters = converted.getAdditionalParameters();
		assertThat(additionalParameters).isNotNull();
		assertThat(additionalParameters).hasSize(2);
		assertThat(additionalParameters).containsEntry("custom_parameter_1", nestedObject);
		assertThat(additionalParameters).containsEntry("custom_parameter_2", "custom-value-2");
	}

}
