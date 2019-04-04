/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.test.oauth2.support;

import static org.springframework.security.test.oauth2.support.CollectionsSupport.nullIfEmpty;
import static org.springframework.security.test.oauth2.support.CollectionsSupport.putIfNotEmpty;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionClaimNames;

/**
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 */
public class AccessTokenAuthenticationBuilder<T extends AccessTokenAuthenticationBuilder<T>>
		extends
		AbstractAuthenticationBuilder<T> {

	public static final String DEFAULT_TOKEN_VALUE = "Bearer test";

	private String tokenValue = DEFAULT_TOKEN_VALUE;

	public T accessToken(final OAuth2AccessToken token) {
		assert (TokenType.BEARER.equals(token.getTokenType()));
		return tokenValue(token.getTokenValue()).scopes(token.getScopes())
				.claim(OAuth2IntrospectionClaimNames.ISSUED_AT, token.getIssuedAt())
				.claim(OAuth2IntrospectionClaimNames.EXPIRES_AT, token.getExpiresAt());
	}

	public T tokenValue(final String tokenValue) {
		this.tokenValue = tokenValue;
		return downCast();
	}

	public T attribute(final String name, final Object value) {
		return claim(name, value);
	}

	public T attributes(final Map<String, Object> attributes) {
		return claims(attributes);
	}

	public OAuth2IntrospectionAuthenticationToken build() {
		if (claims.containsKey(OAuth2IntrospectionClaimNames.TOKEN_TYPE)) {
			throw new RuntimeException(
					OAuth2IntrospectionClaimNames.TOKEN_TYPE
							+ " claim is not configurable (forced to TokenType.BEARER)");
		}
		if (claims.containsKey(OAuth2IntrospectionClaimNames.USERNAME)) {
			throw new RuntimeException(
					OAuth2IntrospectionClaimNames.USERNAME
							+ " claim is not configurable (forced to @WithMockAccessToken.name)");
		}
		claims.put(OAuth2IntrospectionClaimNames.TOKEN_TYPE, TokenType.BEARER);
		putIfNotEmpty(OAuth2IntrospectionClaimNames.USERNAME, name, claims);

		final Set<String> allScopes = getAllScopes();
		putIfNotEmpty(scopeClaimName, allScopes, claims);

		return new OAuth2IntrospectionAuthenticationToken(
				new OAuth2AccessToken(
						TokenType.BEARER,
						tokenValue,
						(Instant) claims.get(OAuth2IntrospectionClaimNames.ISSUED_AT),
						(Instant) claims.get(OAuth2IntrospectionClaimNames.EXPIRES_AT),
						allScopes),
				claims,
				getAllAuthorities(),
				nullIfEmpty(name));
	}

}
