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
public class JwtAuthenticationTokenBuilder<T extends JwtAuthenticationTokenBuilder<T>> {

	private static final String DEFAULT_NAME = "user";

	private static final String[] DEFAULT_AUTHORITIES =  { "ROLE_USER" };

	private static final String DEFAULT_TOKEN_VALUE = "test.jwt.value";

	private static final String DEFAULT_HEADER_NAME = "test-header";

	private static final String DEFAULT_HEADER_VALUE = "test-header-value";

	private static final Map<String, Object> DEFAULT_HEADERS =
			Collections.singletonMap(DEFAULT_HEADER_NAME, DEFAULT_HEADER_VALUE);

	private static final String ROLE_PREFIX = "ROLE_";

	private final Set<GrantedAuthority> authorities;

	private boolean isAuthoritiesSet = false;

	private final Map<String, Object> claims = new HashMap<>();

	private Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter;

	private String tokenValue = DEFAULT_TOKEN_VALUE;

	private final Map<String, Object> headers = new HashMap<>();

	public JwtAuthenticationTokenBuilder() {
		this.authoritiesConverter = new JwtGrantedAuthoritiesConverter();
		name(DEFAULT_NAME);
		this.authorities = new HashSet<>(Arrays.asList(DEFAULT_AUTHORITIES).stream()
				.map(SimpleGrantedAuthority::new).collect(Collectors.toSet()));
	}

	/**
	 * @param jwt fully configured JWT
	 * @return pre-configured builder
	 */
	public T jwt(Jwt token) {
		final Map<String, Object> claims = new HashMap<>(token.getClaims());
		putIfNotEmpty(JwtClaimNames.IAT, token.getIssuedAt(), claims);
		putIfNotEmpty(JwtClaimNames.EXP, token.getExpiresAt(), claims);

		return claims(claims).tokenValue(token.getTokenValue()).name(token.getSubject()).headers(token.getHeaders());
	}

	public T tokenValue(String tokenValue) {
		this.tokenValue = tokenValue;
		return downCast();
	}

	public T name(String name) {
		Assert.hasLength(name, "name must be non empty");
		return claim(JwtClaimNames.SUB, name);
	}

	private T authority(GrantedAuthority authority) {
		Assert.notNull(authority, "authority must be non null");
		if (!this.isAuthoritiesSet) {
			this.authorities.clear();
			this.isAuthoritiesSet = true;
		}
		this.authorities.add(authority);
		return downCast();
	}

	public T authorities(Stream<GrantedAuthority> authorities) {
		this.authorities.clear();
		authorities.forEach(this::authority);
		return downCast();
	}

	public T authorities(GrantedAuthority... authorities) {
		return authorities(Stream.of(authorities));
	}

	public T authorities(Collection<GrantedAuthority> authorities) {
		return authorities(authorities.stream());
	}

	private T role(String role) {
		Assert.hasText(role, "role must be non empty");
		Assert.isTrue(
				!role.startsWith(ROLE_PREFIX),
				"role must not be prefixed with " + ROLE_PREFIX + " (it is auto-added)");
		return authority(new SimpleGrantedAuthority(ROLE_PREFIX + role));
	}

	public T roles(Stream<String> roles) {
		roles.forEach(this::role);
		return downCast();
	}

	public T roles(String... roles) {
		return roles(Stream.of(roles));
	}

	public T roles(Collection<String> roles) {
		return roles(roles.stream());
	}

	public T claim(String name, Object value) {
		Assert.hasText(name, "claim name must be non empty");
		this.claims.put(name, value);
		return downCast();
	}

	public T claims(Map<String, Object> claims) {
		Assert.notNull(claims, "claims must be non null");
		claims.entrySet().stream().forEach(e -> this.claim(e.getKey(), e.getValue()));
		return downCast();
	}

	public T authoritiesConverter(Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
		this.authoritiesConverter = authoritiesConverter;
		return downCast();
	}

	Set<GrantedAuthority> getAllAuthorities(Jwt token) {
		return Stream
				.concat(
						this.authorities.stream(),
						this.authoritiesConverter.convert(token).stream())
				.collect(Collectors.toSet());
	}

	public T header(String name, Object value) {
		Assert.hasText(name, "header name can't be empty");
		this.headers.put(name, value);
		return downCast();
	}

	public T headers(Map<String, Object> headers) {
		Assert.notEmpty(headers, "headers can't be empty");
		this.headers.clear();
		headers.entrySet().stream().forEach(e -> this.header(e.getKey(), e.getValue()));
		return downCast();
	}

	public JwtAuthenticationToken build() {
		final Jwt token = new Jwt(
				this.tokenValue,
				(Instant) this.claims.get(JwtClaimNames.IAT),
				(Instant) this.claims.get(JwtClaimNames.EXP),
				this.headers.isEmpty() ? DEFAULT_HEADERS : this.headers,
				this.claims);

		return new JwtAuthenticationToken(token, getAllAuthorities(token));
	}

	@SuppressWarnings("unchecked")
	protected T downCast() {
		return (T) this;
	}

	private static final Map<String, Object>
			putIfNotEmpty(final String key, final Instant value, final Map<String, Object> map) {
		if (value != null) {
			map.put(key, value);
		}
		return map;
	}

}
