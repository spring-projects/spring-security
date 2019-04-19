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

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

/**
 * @author Rob Winch
 * @since 5.1
 */
public class TestOAuth2AccessTokens {
	
	static Map<String, Object> attributes(){
		final Map<String, Object> attributes = new HashMap<>();
		attributes.put("iat", Instant.now());
		attributes.put("exp", Instant.now().plus(Duration.ofDays(1)));
		return attributes;
	}
	
	public static OAuth2AccessToken noScopes() {
		return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				"no-scopes",
				attributes());
	}

	public static OAuth2AccessToken scopes(String... scopes) {
		return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				"scopes",
				attributes(),
				new HashSet<>(Arrays.asList(scopes)));
	}
}
