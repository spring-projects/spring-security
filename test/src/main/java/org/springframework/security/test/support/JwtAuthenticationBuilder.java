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
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.util.Assert;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 * @since 5.2
 */
public class JwtAuthenticationBuilder<T extends JwtAuthenticationBuilder<T>>
		extends
		AbstractOAuth2AuthenticationBuilder<T, Jwt> {

	public static final String DEFAULT_TOKEN_VALUE = "test.jwt.value";

	public static final String DEFAULT_HEADER_NAME = "test-header";

	public static final String DEFAULT_HEADER_VALUE = "test-header-value";

	public static final Map<String, Object> DEFAULT_HEADERS =
			Collections.singletonMap(DEFAULT_HEADER_NAME, DEFAULT_HEADER_VALUE);

	private String tokenValue = DEFAULT_TOKEN_VALUE;

	private final Map<String, Object> headers = new HashMap<>();

	public JwtAuthenticationBuilder() {
		super(new JwtGrantedAuthoritiesConverter());
	}

	/**
	 * @param jwt fully configured JWT
	 * @return pre-configured builder
	 */
	public T jwt(final Jwt token) {
		final Map<String, Object> claims = new HashMap<>(token.getClaims());
		putIfNotEmpty(JwtClaimNames.IAT, token.getIssuedAt(), claims);
		putIfNotEmpty(JwtClaimNames.EXP, token.getExpiresAt(), claims);

		return claims(claims).tokenValue(token.getTokenValue()).name(token.getSubject()).headers(token.getHeaders());
	}

	public T tokenValue(final String tokenValue) {
		this.tokenValue = tokenValue;
		return downCast();
	}

	public T header(final String name, final Object value) {
		Assert.hasText(name, "Header name can't be empty");
		this.headers.put(name, value);
		return downCast();
	}

	public T headers(final Map<String, Object> headers) {
		Assert.notEmpty(headers, "Headers can't be empty as Jwt constructor throws runtime exception on empty headers.");
		this.headers.clear();
		headers.entrySet().stream().forEach(e -> this.header(e.getKey(), e.getValue()));
		return downCast();
	}

	public JwtAuthenticationToken build() {
		putIfNotEmpty(getNameClaimName(), name, claims);

		final Jwt token = new Jwt(
				tokenValue,
				(Instant) claims.get(JwtClaimNames.IAT),
				(Instant) claims.get(JwtClaimNames.EXP),
				headers.isEmpty() ? DEFAULT_HEADERS : headers,
				claims);

		return new JwtAuthenticationToken(token, getAllAuthorities(token));
	}

	@Override
	protected String getNameClaimName() {
		return JwtClaimNames.SUB;
	}

}
