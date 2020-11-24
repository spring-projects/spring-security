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

import java.util.Collection;
import java.util.LinkedHashSet;

import org.junit.Test;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.TestJwts;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for verifying {@link DelegatingJwtGrantedAuthoritiesConverter}
 *
 * @author Laszlo Stahorszki
 * @author Josh Cummings
 */
public class DelegatingJwtGrantedAuthoritiesConverterTests {

	@Test
	public void convertWhenNoConvertersThenNoAuthorities() {
		DelegatingJwtGrantedAuthoritiesConverter converter = new DelegatingJwtGrantedAuthoritiesConverter();
		Jwt jwt = TestJwts.jwt().build();
		assertThat(converter.convert(jwt)).isEmpty();
	}

	@Test
	public void convertWhenConverterThenAuthorities() {
		DelegatingJwtGrantedAuthoritiesConverter converter = new DelegatingJwtGrantedAuthoritiesConverter(
				((jwt) -> AuthorityUtils.createAuthorityList("one")));
		Jwt jwt = TestJwts.jwt().build();
		Collection<GrantedAuthority> authorities = converter.convert(jwt);
		assertThat(authorityListToOrderedSet(authorities)).containsExactly("one");
	}

	@Test
	public void convertWhenMultipleConvertersThenDuplicatesRemoved() {
		Converter<Jwt, Collection<GrantedAuthority>> one = (jwt) -> AuthorityUtils.createAuthorityList("one", "two");
		Converter<Jwt, Collection<GrantedAuthority>> two = (jwt) -> AuthorityUtils.createAuthorityList("one", "three");
		DelegatingJwtGrantedAuthoritiesConverter composite = new DelegatingJwtGrantedAuthoritiesConverter(one, two);
		Jwt jwt = TestJwts.jwt().build();
		Collection<GrantedAuthority> authorities = composite.convert(jwt);
		assertThat(authorityListToOrderedSet(authorities)).containsExactly("one", "two", "three");
	}

	@Test
	public void constructorWhenAuthoritiesConverterIsNullThenIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(() -> new DelegatingJwtGrantedAuthoritiesConverter(
						(Collection<Converter<Jwt, Collection<GrantedAuthority>>>) null));
	}

	private Collection<String> authorityListToOrderedSet(Collection<GrantedAuthority> grantedAuthorities) {
		Collection<String> authorities = new LinkedHashSet<>(grantedAuthorities.size());
		for (GrantedAuthority authority : grantedAuthorities) {
			authorities.add(authority.getAuthority());
		}
		return authorities;
	}

}
