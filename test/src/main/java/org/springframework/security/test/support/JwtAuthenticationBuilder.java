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
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.util.Assert;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 * @since 5.2
 */
public class JwtAuthenticationBuilder<T extends JwtAuthenticationBuilder<T>> {

	private static final String DEFAULT_NAME = "user";

	private static final String[] DEFAULT_AUTHORITIES =  { "ROLE_USER" };

	private static final String DEFAULT_TOKEN_VALUE = "test.jwt.value";

	private static final String DEFAULT_HEADER_NAME = "test-header";

	private static final String DEFAULT_HEADER_VALUE = "test-header-value";

	private static final Map<String, Object> DEFAULT_HEADERS =
			Collections.singletonMap(DEFAULT_HEADER_NAME, DEFAULT_HEADER_VALUE);

	private static final String ROLE_PREFIX = "ROLE_";

	protected String name;

	protected final Set<String> authorities;

	private boolean isAuthoritiesSet = false;

	protected final Map<String, Object> claims = new HashMap<>();

	protected Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter;

	private String tokenValue = DEFAULT_TOKEN_VALUE;

	private final Map<String, Object> headers = new HashMap<>();

	public JwtAuthenticationBuilder() {
		this.authoritiesConverter = new JwtGrantedAuthoritiesConverter();
		name(DEFAULT_NAME);
		this.authorities = new HashSet<>(Arrays.asList(DEFAULT_AUTHORITIES));
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

	public T authoritiesConverter(final Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
		this.authoritiesConverter = authoritiesConverter;
		return downCast();
	}

	Set<GrantedAuthority> getAllAuthorities(final Jwt token) {
		return Stream
				.concat(
						authorities.stream().map(SimpleGrantedAuthority::new),
						authoritiesConverter.convert(token).stream())
				.collect(Collectors.toSet());
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

	protected String getNameClaimName() {
		return JwtClaimNames.SUB;
	}

	@SuppressWarnings("unchecked")
	protected T downCast() {
		return (T) this;
	}

	private static final Map<String, Object>
			putIfNotEmpty(final String key, final String value, final Map<String, Object> map) {
		if (value != null && !value.isEmpty()) {
			map.put(key, value);
		}
		return map;
	}

	private static final Map<String, Object>
			putIfNotEmpty(final String key, final Instant value, final Map<String, Object> map) {
		if (value != null) {
			map.put(key, value);
		}
		return map;
	}

}
