/*
 * Copyright 2002-2020 the original author or authors.
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
import java.util.Map;
import java.util.Set;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;

/**
 * Tests for {@link MapOAuth2AccessTokenResponseConverter}.
 *
 * @author Nikita Konev
 */
public class MapOAuth2AccessTokenResponseConverterTests {

	private MapOAuth2AccessTokenResponseConverter messageConverter;

	@Before
	public void setup() {
		this.messageConverter = new MapOAuth2AccessTokenResponseConverter();
	}

	@Test
	public void shouldConvertFull() {
		Map<String, String> map = new HashMap<>();
		map.put("access_token", "access-token-1234");
		map.put("token_type", "bearer");
		map.put("expires_in", "3600");
		map.put("scope", "read write");
		map.put("refresh_token", "refresh-token-1234");
		map.put("custom_parameter_1", "custom-value-1");
		map.put("custom_parameter_2", "custom-value-2");
		OAuth2AccessTokenResponse converted = messageConverter.convert(map);
		OAuth2AccessToken accessToken = converted.getAccessToken();
		Assert.assertNotNull(accessToken);
		Assert.assertEquals("access-token-1234", accessToken.getTokenValue());
		Assert.assertEquals(OAuth2AccessToken.TokenType.BEARER, accessToken.getTokenType());
		Set<String> scopes = accessToken.getScopes();
		Assert.assertNotNull(scopes);
		Assert.assertEquals(2, scopes.size());
		Assert.assertTrue(scopes.contains("read"));
		Assert.assertTrue(scopes.contains("write"));
		Assert.assertEquals(3600, Duration.between(accessToken.getIssuedAt(), accessToken.getExpiresAt()).getSeconds());

		OAuth2RefreshToken refreshToken = converted.getRefreshToken();
		Assert.assertNotNull(refreshToken);
		Assert.assertEquals("refresh-token-1234", refreshToken.getTokenValue());

		Map<String, Object> additionalParameters = converted.getAdditionalParameters();
		Assert.assertNotNull(additionalParameters);
		Assert.assertEquals(2, additionalParameters.size());
		Assert.assertEquals("custom-value-1", additionalParameters.get("custom_parameter_1"));
		Assert.assertEquals("custom-value-2", additionalParameters.get("custom_parameter_2"));
	}

	@Test
	public void shouldConvertMinimal() {
		Map<String, String> map = new HashMap<>();
		map.put("access_token", "access-token-1234");
		map.put("token_type", "bearer");
		OAuth2AccessTokenResponse converted = messageConverter.convert(map);
		OAuth2AccessToken accessToken = converted.getAccessToken();
		Assert.assertNotNull(accessToken);
		Assert.assertEquals("access-token-1234", accessToken.getTokenValue());
		Assert.assertEquals(OAuth2AccessToken.TokenType.BEARER, accessToken.getTokenType());
		Set<String> scopes = accessToken.getScopes();
		Assert.assertNotNull(scopes);
		Assert.assertEquals(0, scopes.size());

		Assert.assertEquals(1, Duration.between(accessToken.getIssuedAt(), accessToken.getExpiresAt()).getSeconds());

		OAuth2RefreshToken refreshToken = converted.getRefreshToken();
		Assert.assertNull(refreshToken);

		Map<String, Object> additionalParameters = converted.getAdditionalParameters();
		Assert.assertNotNull(additionalParameters);
		Assert.assertEquals(0, additionalParameters.size());
	}

	@Test
	public void shouldConvertWithUnsupportedExpiresIn() {
		Map<String, String> map = new HashMap<>();
		map.put("access_token", "access-token-1234");
		map.put("token_type", "bearer");
		map.put("expires_in", "2100-01-01-abc");
		OAuth2AccessTokenResponse converted = messageConverter.convert(map);
		OAuth2AccessToken accessToken = converted.getAccessToken();
		Assert.assertNotNull(accessToken);
		Assert.assertEquals("access-token-1234", accessToken.getTokenValue());
		Assert.assertEquals(OAuth2AccessToken.TokenType.BEARER, accessToken.getTokenType());
		Set<String> scopes = accessToken.getScopes();
		Assert.assertNotNull(scopes);
		Assert.assertEquals(0, scopes.size());

		Assert.assertEquals(1, Duration.between(accessToken.getIssuedAt(), accessToken.getExpiresAt()).getSeconds());

		OAuth2RefreshToken refreshToken = converted.getRefreshToken();
		Assert.assertNull(refreshToken);

		Map<String, Object> additionalParameters = converted.getAdditionalParameters();
		Assert.assertNotNull(additionalParameters);
		Assert.assertEquals(0, additionalParameters.size());
	}

}
