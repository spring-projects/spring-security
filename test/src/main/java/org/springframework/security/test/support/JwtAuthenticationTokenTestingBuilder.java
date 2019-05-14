/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.test.support;

import java.util.Collection;
import java.util.HashSet;
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
import org.springframework.util.StringUtils;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 * @since 5.2
 */
public class JwtAuthenticationTokenTestingBuilder<T extends JwtAuthenticationTokenTestingBuilder<T>>
		extends
		JwtAuthenticationToken.Builder<T>
		implements
		AuthenticationBuilder<JwtAuthenticationToken> {

	private static final String[] DEFAULT_SCOPES = { "USER" };

	private final Set<GrantedAuthority> addedAuthorities;

	public JwtAuthenticationTokenTestingBuilder(Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
		super(new JwtTestingBuilder(), authoritiesConverter);
		this.addedAuthorities = new HashSet<>();
		scopes(DEFAULT_SCOPES);
	}

	public JwtAuthenticationTokenTestingBuilder() {
		this(new JwtGrantedAuthoritiesConverter());
	}

	/**
	 * How to extract authorities from token
	 * @param authoritiesConverter JWT to granted-authorities converter
	 * @return this builder to further configure
	 */
	public T authorities(Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
		return authoritiesConverter(authoritiesConverter);
	}

	/**
	 * Adds authorities to what is extracted from the token.<br>
	 * Please consider using {@link #authorities(Converter)} instead.
	 * @param authorities authorities to add to token ones
	 * @return this builder to further configure
	 */
	public T authorities(Stream<GrantedAuthority> authorities) {
		addedAuthorities.addAll(authorities.collect(Collectors.toSet()));
		return downcast();
	}

	/**
	 * Adds authorities to what is extracted from the token.<br>
	 * Please consider using {@link #authorities(Converter)} instead.
	 * @param authorities authorities to add to token ones
	 * @return this builder to further configure
	 */
	public T authorities(GrantedAuthority... authorities) {
		return authorities(Stream.of(authorities));
	}

	/**
	 * Adds authorities to what is extracted from the token.<br>
	 * Please consider using {@link #authorities(Converter)} instead.
	 * @param authorities authorities to add to token ones
	 * @return this builder to further configure
	 */
	public T authorities(String... authorities) {
		return authorities(Stream.of(authorities).map(SimpleGrantedAuthority::new));
	}

	@Override
	public JwtAuthenticationToken build() {
		final Jwt token = getToken();

		return new JwtAuthenticationToken(token, getAuthorities(token));
	}

	@Override
	protected Collection<GrantedAuthority> getAuthorities(Jwt token) {
		final Collection<GrantedAuthority> principalAuthorities = super.getAuthorities(token);

		return addedAuthorities.isEmpty() ? principalAuthorities
				: Stream.concat(principalAuthorities.stream(), addedAuthorities.stream()).collect(Collectors.toSet());
	}

	/**
	 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
	 * @since 5.2
	 */
	static class JwtTestingBuilder extends Jwt.Builder<JwtTestingBuilder> {

		private static final String DEFAULT_SUBJECT = "user";

		private static final String DEFAULT_TOKEN_VALUE = "test.jwt.value";

		private static final String DEFAULT_HEADER_NAME = "test-header";

		private static final String DEFAULT_HEADER_VALUE = "test-header-value";

		public JwtTestingBuilder() {
			super();
		}

		@Override
		public Jwt build() {
			final Object subjectClaim = claims.get(JwtClaimNames.SUB);
			if (!StringUtils.hasLength(tokenValue)) {
				tokenValue(DEFAULT_TOKEN_VALUE);
			}
			if (!StringUtils.hasLength((String) subjectClaim)) {
				claim(JwtClaimNames.SUB, DEFAULT_SUBJECT);
			}
			if (headers.size() == 0) {
				header(DEFAULT_HEADER_NAME, DEFAULT_HEADER_VALUE);
			}
			return super.build();
		}
	}
}
