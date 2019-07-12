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
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.StringUtils;

/**
 * Extracts the {@link GrantedAuthority}s from scope attributes typically found in a
 * {@link Jwt}.
 *
 * @author Eric Deandrea
 * @since 5.2
 */
public final class JwtGrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
	private static final String DEFAULT_AUTHORITIES_CLAIM = "authorities";
	private static final String DEFAULT_AUTHORITIES_PREFIX = "";
	private static final Collection<String> WELL_KNOWN_SCOPE_ATTRIBUTE_NAMES =
			Arrays.asList("scope", "scp");
	
	private String prefix;
	
	private String authoritiesClaimName;

	public JwtGrantedAuthoritiesConverter(String prefix, String authoritiesClaim) {
		super();
		this.prefix = prefix;
		this.authoritiesClaimName = authoritiesClaim;
	}
	
	public JwtGrantedAuthoritiesConverter() {
		this("SCOPE_", "scope");
	}

	public String getPrefix() {
		return prefix;
	}

	public void setPrefix(String prefix) {
		this.prefix = prefix;
	}

	public String getAuthoritiesClaimName() {
		return authoritiesClaimName;
	}

	public void setAuthoritiesClaimName(String authoritiesClaim) {
		this.authoritiesClaimName = authoritiesClaim;
	}

	/**
	 * Extracts the authorities
	 * @param jwt The {@link Jwt} token
	 * @return The {@link GrantedAuthority authorities} read from the token scopes
	 */
	@Override
	public Collection<GrantedAuthority> convert(Jwt jwt) {
		Collection<String> authoritiesNames = WELL_KNOWN_SCOPE_ATTRIBUTE_NAMES.contains(authoritiesClaimName) ? getScopes(jwt) : jwt.getClaimAsStringList(authoritiesClaimName);
		if(authoritiesNames == null) {
			return null;
		}
		return authoritiesNames
				.stream()
				.map(authority -> prefix + authority)
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toList());
	}

	/**
	 * Gets the scopes from a {@link Jwt} token
	 * @param jwt The {@link Jwt} token
	 * @return The scopes from the token
	 */
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
