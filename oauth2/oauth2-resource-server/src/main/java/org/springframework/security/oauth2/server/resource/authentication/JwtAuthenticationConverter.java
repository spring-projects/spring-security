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

package org.springframework.security.oauth2.server.resource.authentication;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.stream.Collectors;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.StringUtils;

/**
 * @author Rob Winch
 * @author Josh Cummings
 * @since 5.1
 */
public class JwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {
	private static final String SCOPE_AUTHORITY_PREFIX = "SCOPE_";

	private static final Collection<String> WELL_KNOWN_SCOPE_ATTRIBUTE_NAMES =
			Arrays.asList("scope", "scp");


	public final AbstractAuthenticationToken convert(Jwt jwt) {
		Collection<GrantedAuthority> authorities = extractAuthorities(jwt);
		return new JwtAuthenticationToken(jwt, authorities);
	}

	protected Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
		return this.getScopes(jwt)
						.stream()
						.map(authority -> SCOPE_AUTHORITY_PREFIX + authority)
						.map(SimpleGrantedAuthority::new)
						.collect(Collectors.toList());
	}

	private Collection<String> getScopes(Jwt jwt) {
		for ( String attributeName : WELL_KNOWN_SCOPE_ATTRIBUTE_NAMES ) {
			Object scopes = jwt.getClaims().get(attributeName);
			if (scopes instanceof String) {
				if (StringUtils.hasText((String) scopes)) {
					return Arrays.asList(((String) scopes).split(" "));
				} else {
					return Collections.emptyList();
				}
			} else if (scopes instanceof Collection) {
				return (Collection<String>) scopes;
			}
		}

		return Collections.emptyList();
	}
}
