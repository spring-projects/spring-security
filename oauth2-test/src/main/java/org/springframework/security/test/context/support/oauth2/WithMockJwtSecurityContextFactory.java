/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.test.context.support.oauth2;

import static org.springframework.security.test.context.support.oauth2.AnnotationHelper.putIfNotEmpty;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

/**
 * Create a {@link org.springframework.security.core.context.SecurityContext SecurityContext} populated with a
 * {@link org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
 * JwtAuthenticationToken} containing a {@link org.springframework.security.oauth2.jwt.Jwt JWT} as described by
 * {@link org.springframework.security.test.context.support.oauth2.WithMockJwt @WithMockJwt}
 *
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 *
 */
public final class WithMockJwtSecurityContextFactory implements WithSecurityContextFactory<WithMockJwt> {
	public static final String DEFAULT_TOKEN_VALUE = "test.jwt.value";

	@Override
	public SecurityContext createSecurityContext(final WithMockJwt annotation) {
		final AttributeParsersHelper parsersHelper =
				AttributeParsersHelper.withDefaultParsers(annotation.additionalParsers());

		final Map<String, Object> headers = parsersHelper.parse(annotation.headers());

		final Map<String, Object> claims = new HashMap<>(parsersHelper.parse(annotation.claims()));
		if (claims.containsKey(JwtClaimNames.SUB)) {
			throw new RuntimeException(JwtClaimNames.SUB + " claim is not configurable (forced to @WithMockJwt.name)");
		} else {
			putIfNotEmpty(JwtClaimNames.SUB, annotation.name(), claims);
		}

		final AuthoritiesAndScopes authoritiesAndScopes =
				AuthoritiesAndScopes.get(annotation.authorities(), new String[] {}, claims);

		final SecurityContext context = SecurityContextHolder.createEmptyContext();
		context.setAuthentication(
				new JwtAuthenticationToken(
						new Jwt(
								DEFAULT_TOKEN_VALUE,
								(Instant) claims.get(JwtClaimNames.IAT),
								(Instant) claims.get(JwtClaimNames.EXP),
								headers,
								claims),
						authoritiesAndScopes.authorities));

		return context;
	}
}