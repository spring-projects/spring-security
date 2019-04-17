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
package org.springframework.security.oauth2.server.resource.authentication;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Submits {@link Jwt} claims to provided scopes converter and then 
 * builds {@link GrantedAuthority}s out of extracted scopes, prefixing it with "SCOPE_".
 *
 * @author Eric Deandrea
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 * @since 5.2
 */
public final class JwtScopesGrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
	private static final String DEFAULT_SCOPE_AUTHORITY_PREFIX = "SCOPE_";

	private Converter<Map<String, Object>, Set<String>> scopesConverter;
	private String authoritiesPrefix;

	/**
	 * @param scopesConverter used to extract scopes from token claims
	 * @param authoritiesPrefix prefix to add to scopes before turning it into {@link SimpleGrantedAuthority authorities}
	 */
	public JwtScopesGrantedAuthoritiesConverter(
			final Converter<Map<String, Object>, Set<String>> scopesConverter,
			final String authoritiesPrefix) {
		this.scopesConverter = scopesConverter;
		this.authoritiesPrefix = authoritiesPrefix;
	}

	/**
	 * Defaults authorities prefix to {@value #DEFAULT_SCOPE_AUTHORITY_PREFIX}
	 * @param scopesConverter used to extract scopes from token claims
	 */
	@Autowired
	public JwtScopesGrantedAuthoritiesConverter(
			final Converter<Map<String, Object>, Set<String>> scopesConverter) {
		this(scopesConverter, DEFAULT_SCOPE_AUTHORITY_PREFIX);
	}
	
	/**
	 * Defaults scopes converter to a reasonable one
	 * @param authoritiesPrefix prefix to add to scopes before turning it into {@link SimpleGrantedAuthority authorities}
	 * @see TokenAttributesScopesConverter
	 */
	public JwtScopesGrantedAuthoritiesConverter(final String authoritiesPrefix) {
		this(new TokenAttributesScopesConverter(), authoritiesPrefix);
	}

	/**
	 * Defaults scopes converter to a reasonable one and authorities prefix to {@value #DEFAULT_SCOPE_AUTHORITY_PREFIX}
	 * @see TokenAttributesScopesConverter
	 */
	public JwtScopesGrantedAuthoritiesConverter() {
		this(DEFAULT_SCOPE_AUTHORITY_PREFIX);
	}

	/**
	 * Extracts the authorities
	 * @param jwt The {@link Jwt} token
	 * @return The {@link GrantedAuthority authorities} read from the token scopes
	 */
	@Override
	public Collection<GrantedAuthority> convert(final Jwt jwt) {
		return scopesConverter.convert(jwt.getClaims())
				.stream()
				.map(authority -> authoritiesPrefix + authority)
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toList());
	}

	public void setScopesConverter(final Converter<Map<String, Object>, Set<String>> scopesConverter) {
		this.scopesConverter = scopesConverter;
	}

	public void setAuthoritiesPrefix(final String authoritiesPrefix) {
		this.authoritiesPrefix = authoritiesPrefix;
	}
	
}
