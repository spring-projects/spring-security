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
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 * @since 5.2
 */
public abstract class AbstractOAuth2AuthenticationBuilder<T extends AbstractOAuth2AuthenticationBuilder<T, PRINCIPAL_TYPE>, PRINCIPAL_TYPE extends AbstractOAuth2Token> {

	private static final String ROLE_PREFIX = "ROLE_";

	protected String name;

	protected final Set<String> authorities;

	private boolean isAuthoritiesSet = false;

	protected final Map<String, Object> claims = new HashMap<>();

	protected Converter<PRINCIPAL_TYPE, Collection<GrantedAuthority>> authoritiesConverter;

	protected abstract String getNameClaimName();

	public AbstractOAuth2AuthenticationBuilder(
			final Converter<PRINCIPAL_TYPE, Collection<GrantedAuthority>> authoritiesConverter,
			final String defaultName,
			final String[] defaultAuthorities) {
		this.authoritiesConverter = authoritiesConverter;
		name(defaultName);
		this.authorities = new HashSet<>(Arrays.asList(defaultAuthorities));
	}

	public AbstractOAuth2AuthenticationBuilder(
			final Converter<PRINCIPAL_TYPE, Collection<GrantedAuthority>> authoritiesConverter) {
		this(authoritiesConverter, Defaults.AUTH_NAME, Defaults.AUTHORITIES);
	}

	public T name(final String name) {
		this.name = name;
		return downCast();
	}

	public T authority(final String authority) {
		Assert.hasText(authority, "authority must be non empty");
		if (!this.isAuthoritiesSet) {
			this.authorities.clear();
			this.isAuthoritiesSet = true;
		}
		this.authorities.add(authority);
		return downCast();
	}

	public T authorities(final Stream<String> authorities) {
		this.authorities.clear();
		authorities.forEach(this::authority);
		return downCast();
	}

	public T authorities(final String... authorities) {
		return authorities(Stream.of(authorities));
	}

	public T authorities(final Collection<String> authorities) {
		return authorities(authorities.stream());
	}

	public T role(final String role) {
		Assert.hasText(role, "authority must be non empty");
		Assert.isTrue(
				!role.startsWith(ROLE_PREFIX),
				"role must not be prefixed with " + ROLE_PREFIX + " (it is auto-added)");
		return authority(ROLE_PREFIX + role);
	}

	public T roles(final Stream<String> roles) {
		this.authorities.removeIf(a -> a.startsWith(ROLE_PREFIX));
		roles.forEach(this::role);
		return downCast();
	}

	public T roles(final String... roles) {
		return roles(Stream.of(roles));
	}

	public T roles(final Collection<String> roles) {
		return roles(roles.stream());
	}

	public T claim(final String name, final Object value) {
		Assert.hasText(name, "Claim name must be non empty");
		if (getNameClaimName().equals(name)) {
			return name(value.toString());
		}
		this.claims.put(name, value);
		return downCast();
	}

	public T claims(final Map<String, Object> attributes) {
		Assert.notNull(attributes, "attributes must be non null");
		this.claims.clear();
		attributes.entrySet().stream().forEach(e -> this.claim(e.getKey(), e.getValue()));
		return downCast();
	}

	public T authoritiesConverter(final Converter<PRINCIPAL_TYPE, Collection<GrantedAuthority>> authoritiesConverter) {
		this.authoritiesConverter = authoritiesConverter;
		return downCast();
	}

	Set<GrantedAuthority> getAllAuthorities(final PRINCIPAL_TYPE token) {
		return Stream
				.concat(
						authorities.stream().map(SimpleGrantedAuthority::new),
						authoritiesConverter.convert(token).stream())
				.collect(Collectors.toSet());
	}

	@SuppressWarnings("unchecked")
	protected T downCast() {
		return (T) this;
	}

	protected static String nullIfEmpty(final String str) {
		return StringUtils.isEmpty(str) ? null : str;
	}

	protected static final Map<String, Object>
			putIfNotEmpty(final String key, final String value, final Map<String, Object> map) {
		if (value != null && !value.isEmpty()) {
			map.put(key, value);
		}
		return map;
	}

	protected static final Map<String, Object>
			putIfNotEmpty(final String key, final Instant value, final Map<String, Object> map) {
		if (value != null) {
			map.put(key, value);
		}
		return map;
	}

	protected static final Map<String, Object>
			putIfNotEmpty(final String key, final Collection<String> value, final Map<String, Object> map) {
		if (value != null && !value.isEmpty()) {
			map.put(key, value);
		}
		return map;
	}

	protected static Set<String> getScopes(final Object scopesClaim, final Collection<String> authorities) {
		@SuppressWarnings("unchecked")
		Stream<String> claimsScopes = scopesClaim == null ? Stream.empty() : ((Collection<String>)scopesClaim).stream();
		Stream<String> authoritiesScopes = authorities.stream().filter(s -> s.startsWith("SCOPE_")).map(s -> s.substring(6));
		return Stream.concat(claimsScopes, authoritiesScopes).collect(Collectors.toSet());
	}
}
