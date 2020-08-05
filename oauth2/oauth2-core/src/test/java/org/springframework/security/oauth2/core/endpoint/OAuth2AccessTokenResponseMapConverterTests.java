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

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import org.springframework.security.oauth2.core.OAuth2AccessToken;

/**
 * Tests for {@link OAuth2AccessTokenResponseMapConverter}.
 *
 * @author Nikita Konev
 */
public class OAuth2AccessTokenResponseMapConverterTests {

	private OAuth2AccessTokenResponseMapConverter messageConverter;

	@Before
	public void setup() {
		this.messageConverter = new OAuth2AccessTokenResponseMapConverter();
	}

	@Test
	public void convertFull() {
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put("custom_parameter_1", "custom-value-1");
		additionalParameters.put("custom_parameter_2", "custom-value-2");

		Set<String> scopes = new HashSet<>();
		scopes.add("read");
		scopes.add("write");

		OAuth2AccessTokenResponse build = OAuth2AccessTokenResponse.withToken("access-token-value-1234").expiresIn(3699)
				.additionalParameters(additionalParameters).refreshToken("refresh-token-value-1234").scopes(scopes)
				.tokenType(OAuth2AccessToken.TokenType.BEARER).build();
		Map<String, String> result = messageConverter.convert(build);
		Assert.assertEquals(7, result.size());

		Assert.assertEquals("access-token-value-1234", result.get("access_token"));
		Assert.assertEquals("refresh-token-value-1234", result.get("refresh_token"));
		Assert.assertEquals("read write", result.get("scope"));
		Assert.assertEquals("Bearer", result.get("token_type"));
		Assert.assertNotNull(result.get("expires_in"));
		Assert.assertEquals("custom-value-1", result.get("custom_parameter_1"));
		Assert.assertEquals("custom-value-2", result.get("custom_parameter_2"));
	}

	@Test
	public void convertMinimal() {
		OAuth2AccessTokenResponse build = OAuth2AccessTokenResponse.withToken("access-token-value-1234")
				.tokenType(OAuth2AccessToken.TokenType.BEARER).build();
		Map<String, String> result = messageConverter.convert(build);
		Assert.assertEquals(3, result.size());

		Assert.assertEquals("access-token-value-1234", result.get("access_token"));
		Assert.assertEquals("Bearer", result.get("token_type"));
		Assert.assertNotNull(result.get("expires_in"));
	}

}
