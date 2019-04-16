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
package org.springframework.security.test.support;

import java.time.Instant;
import java.util.Map;

import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionClaimNames;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 * @since 5.2
 */
public class AccessTokenAuthenticationBuilder<T extends AccessTokenAuthenticationBuilder<T>>
		extends
		AbstractOAuth2AuthenticationBuilder<T, OAuth2AccessToken> {
	protected static final String DEFAULT_TOKEN_VALUE = "Bearer mocked token";

	private String tokenValue = DEFAULT_TOKEN_VALUE;

	private TokenType tokenType = TokenType.BEARER;

	public AccessTokenAuthenticationBuilder() {
		super(new AccessTokenGrantedAuthoritiesConverter());
	}

	public T tokenValue(final String tokenValue) {
		this.tokenValue = tokenValue;
		return downCast();
	}

	public T tokenType(final TokenType tokenType) {
		this.tokenType = tokenType;
		return downCast();
	}

	public T attribute(final String name, final Object value) {
		return claim(name, value);
	}

	public T attributes(final Map<String, Object> attributes) {
		return claims(attributes);
	}

	public OAuth2IntrospectionAuthenticationToken build() {
		claims.put(OAuth2IntrospectionClaimNames.TOKEN_TYPE, tokenType);
		putIfNotEmpty(getNameClaimName(), name, claims);

		final OAuth2AccessToken token = new OAuth2AccessToken(
				tokenType,
				tokenValue,
				(Instant) claims.get(OAuth2IntrospectionClaimNames.ISSUED_AT),
				(Instant) claims.get(OAuth2IntrospectionClaimNames.EXPIRES_AT),
				getScopes(claims.get(OAuth2IntrospectionClaimNames.SCOPE), authorities));

		return new OAuth2IntrospectionAuthenticationToken(token, claims, getAllAuthorities(token), nullIfEmpty(name));
	}

	@Override
	protected String getNameClaimName() {
		return OAuth2IntrospectionClaimNames.USERNAME;
	}

}
