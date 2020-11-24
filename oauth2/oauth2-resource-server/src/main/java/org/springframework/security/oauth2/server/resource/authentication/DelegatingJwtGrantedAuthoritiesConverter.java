/*
 * Copyright 2002-2020 the original author or authors.
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashSet;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;

/**
 * A {@link Jwt} to {@link GrantedAuthority} {@link Converter} that is a composite of
 * converters.
 *
 * @author Laszlo Stahorszki
 * @author Josh Cummings
 * @since 5.5
 * @see org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter
 */
public class DelegatingJwtGrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

	private final Collection<Converter<Jwt, Collection<GrantedAuthority>>> authoritiesConverters;

	/**
	 * Constructs a {@link DelegatingJwtGrantedAuthoritiesConverter} using the provided
	 * {@link Collection} of {@link Converter}s
	 * @param authoritiesConverters the {@link Collection} of {@link Converter}s to use
	 */
	public DelegatingJwtGrantedAuthoritiesConverter(
			Collection<Converter<Jwt, Collection<GrantedAuthority>>> authoritiesConverters) {
		Assert.notNull(authoritiesConverters, "authoritiesConverters cannot be null");
		this.authoritiesConverters = new ArrayList<>(authoritiesConverters);
	}

	/**
	 * Constructs a {@link DelegatingJwtGrantedAuthoritiesConverter} using the provided
	 * array of {@link Converter}s
	 * @param authoritiesConverters the array of {@link Converter}s to use
	 */
	@SafeVarargs
	public DelegatingJwtGrantedAuthoritiesConverter(
			Converter<Jwt, Collection<GrantedAuthority>>... authoritiesConverters) {
		this(Arrays.asList(authoritiesConverters));
	}

	/**
	 * Extract {@link GrantedAuthority}s from the given {@link Jwt}.
	 * <p>
	 * The authorities are extracted from each delegated {@link Converter} one at a time.
	 * For each converter, its authorities are added in order, with duplicates removed.
	 * @param jwt The {@link Jwt} token
	 * @return The {@link GrantedAuthority authorities} read from the token scopes
	 */
	@Override
	public Collection<GrantedAuthority> convert(Jwt jwt) {
		Collection<GrantedAuthority> result = new LinkedHashSet<>();

		for (Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter : this.authoritiesConverters) {
			Collection<GrantedAuthority> authorities = authoritiesConverter.convert(jwt);
			if (authorities != null) {
				result.addAll(authorities);
			}
		}

		return result;
	}

}
