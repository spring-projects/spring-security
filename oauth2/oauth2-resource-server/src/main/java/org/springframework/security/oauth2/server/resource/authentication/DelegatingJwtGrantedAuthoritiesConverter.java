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

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashSet;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Implementation of {@link Converter} that wraps multiple {@link Converter} instances into one.
 *
 * @author Laszlo Stahorszki
 * @since 5.5
 */
public class DelegatingJwtGrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

	private final Collection<Converter<Jwt, Collection<GrantedAuthority>>> converters = new HashSet<>();

	/**
	 * Constructs a {@link DelegatingJwtGrantedAuthoritiesConverter} using the provided {@link Collection} of
	 * {@link Converter}s
	 *
	 * @param converters the {@link Collection} of {@link Converter}s to use
	 */
	public DelegatingJwtGrantedAuthoritiesConverter(Collection<Converter<Jwt, Collection<GrantedAuthority>>> converters) {
		this.converters.addAll(converters);
	}

	/**
	 * Constructs a {@link DelegatingJwtGrantedAuthoritiesConverter} using the provided array of
	 * {@link Converter}s
	 *
	 * @param converters the array of {@link Converter}s to use
	 */
	@SafeVarargs
	public DelegatingJwtGrantedAuthoritiesConverter(Converter<Jwt, Collection<GrantedAuthority>>... converters) {
		this(Arrays.asList(converters));
	}

	/**
	 * Collects the {@link Collection} of authorities from the provided {@link Jwt} token. The method iterates through
	 * all the {@link Converter}s provided during construction and returns the union of {@link GrantedAuthority}s
	 * they extract.
	 * @param source the source object to convert, which must be an instance of {@code S} (never {@code null})
	 * @return the converted object, which must be an instance of {@code T} (potentially {@code null})
	 * @throws IllegalArgumentException if the source cannot be converted to the desired target type
	 */
	@Override
	public Collection<GrantedAuthority> convert(Jwt source) {
		Collection<GrantedAuthority> result = new LinkedHashSet<>();

		for (Converter<Jwt, Collection<GrantedAuthority>> converter: this.converters) {
			Collection<GrantedAuthority> authorities = converter.convert(source);
			if (authorities != null) {
				result.addAll(authorities);
			}
		}

		return result;
	}
}
