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
import java.util.Collection;
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
public class JwtSupport {
	public static final String DEFAULT_TOKEN_VALUE = "test.jwt.value";
	public static final String DEFAULT_HEADER_NAME = "test-header";
	public static final String DEFAULT_HEADER_VALUE = "abracadabra";
	public static final Map<String, Object> DEFAULT_HEADERS =
			Collections.singletonMap(DEFAULT_HEADER_NAME, DEFAULT_HEADER_VALUE);

	public static JwtAuthenticationToken authentication(
			final String name,
			final Collection<String> authorities,
			final Collection<String> scopes,
			final Map<String, Object> claims,
			final Map<String, Object> headers) {
		final Map<String, Object> postrPocessedClaims = new HashMap<>(claims);
		if (claims.containsKey(JwtClaimNames.SUB)) {
			throw new RuntimeException(JwtClaimNames.SUB + " claim is not configurable (forced to \"name\")");
		} else {
			putIfNotEmpty(JwtClaimNames.SUB, name, postrPocessedClaims);
		}

		final AuthoritiesAndScopes authoritiesAndScopes =
				AuthoritiesAndScopes.get(authorities, scopes, postrPocessedClaims);

		return new JwtAuthenticationToken(
				new Jwt(
						DEFAULT_TOKEN_VALUE,
						(Instant) postrPocessedClaims.get(JwtClaimNames.IAT),
						(Instant) postrPocessedClaims.get(JwtClaimNames.EXP),
						headers,
						postrPocessedClaims),
				authoritiesAndScopes.authorities);
	}
}
