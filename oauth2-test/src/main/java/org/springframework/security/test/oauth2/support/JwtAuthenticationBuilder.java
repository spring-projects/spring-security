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

import static org.springframework.security.test.oauth2.support.CollectionsSupport.putIfNotEmpty;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 */
public class JwtAuthenticationBuilder<T extends JwtAuthenticationBuilder<T>> extends AbstractAuthenticationBuilder<T> {

	public static final String DEFAULT_TOKEN_VALUE = "test.jwt.value";

	public static final String DEFAULT_HEADER_NAME = "test-header";

	public static final String DEFAULT_HEADER_VALUE = "abracadabra";

	public static final Map<String, Object> DEFAULT_HEADERS =
			Collections.singletonMap(DEFAULT_HEADER_NAME, DEFAULT_HEADER_VALUE);

	private String tokenValue = DEFAULT_TOKEN_VALUE;

	private Map<String, Object> headers = DEFAULT_HEADERS;

	private boolean isHeadersSet = false;

	/**
	 * Solely claims will be considered at build() time. token properties that can be
	 * stored as claims (audience, expiresAt, id, issuedAt, issuer, notBefore) are
	 * ignored.
	 * @param jwt fully configured JWT
	 * @return pre-configured builder
	 */
	public T jwt(final Jwt jwt) {
		final Map<String, Object> claims = new HashMap<>(jwt.getClaims());
		if (jwt.getIssuedAt() != null) {
			if (jwt.getClaims().containsKey(JwtClaimNames.IAT)
					&& !jwt.getIssuedAt().equals(jwt.getClaimAsInstant(JwtClaimNames.IAT))) {
				throw new RuntimeException(
						"Inconsistent issue instants: jwt.getIssuedAt() = " + jwt.getIssuedAt()
								+ " but jwt.getClaimAsInstant(JwtClaimNames.IAT) = "
								+ jwt.getClaimAsInstant(JwtClaimNames.IAT));
			}
			claims.put(JwtClaimNames.IAT, jwt.getIssuedAt());
		}
		if (jwt.getExpiresAt() != null) {
			if (jwt.getClaims().containsKey(JwtClaimNames.EXP)
					&& !jwt.getExpiresAt().equals(jwt.getClaimAsInstant(JwtClaimNames.EXP))) {
				throw new RuntimeException(
						"Inconsistent expiry instants: jwt.getExpiresAt() = " + jwt.getExpiresAt()
								+ " but jwt.getClaimAsInstant(JwtClaimNames.EXP) = "
								+ jwt.getClaimAsInstant(JwtClaimNames.EXP));
			}
			claims.put(JwtClaimNames.EXP, jwt.getExpiresAt());
		}
		return tokenValue(jwt.getTokenValue()).name(jwt.getSubject()).claims(jwt.getClaims()).headers(jwt.getHeaders());
	}

	public T tokenValue(final String tokenValue) {
		this.tokenValue = tokenValue;
		return downCast();
	}

	public T header(final String name, final Object value) {
		assert (name != null);
		if (this.isHeadersSet == false) {
			this.headers = new HashMap<>();
			this.isHeadersSet = true;
		}
		this.headers.put(name, value);
		return downCast();
	}

	public T headers(final Map<String, Object> headers) {
		assert (headers != null);
		headers.entrySet().stream().forEach(e -> this.header(e.getKey(), e.getValue()));
		return downCast();
	}

	public JwtAuthenticationToken build() {
		if (claims.containsKey(JwtClaimNames.SUB) && !claims.get(JwtClaimNames.SUB).equals(name)) {
			throw new RuntimeException(JwtClaimNames.SUB + " claim is not configurable (forced to \"name\")");
		} else {
			putIfNotEmpty(JwtClaimNames.SUB, name, claims);
		}

		putIfNotEmpty(scopeClaimName, getAllScopes(), claims);

		return new JwtAuthenticationToken(
				new Jwt(
						tokenValue,
						(Instant) claims.get(JwtClaimNames.IAT),
						(Instant) claims.get(JwtClaimNames.EXP),
						headers,
						claims),
				getAllAuthorities());
	}

}
