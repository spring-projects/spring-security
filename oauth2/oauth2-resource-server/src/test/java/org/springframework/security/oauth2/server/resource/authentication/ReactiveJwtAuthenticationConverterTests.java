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

import java.util.Collection;

import org.junit.Test;
import reactor.core.publisher.Flux;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.springframework.security.oauth2.jwt.TestJwts.jwt;

/**
 * Tests for {@link ReactiveJwtAuthenticationConverter}
 *
 * @author Eric Deandrea
 * @since 5.2
 */
public class ReactiveJwtAuthenticationConverterTests {

	ReactiveJwtAuthenticationConverter jwtAuthenticationConverter = new ReactiveJwtAuthenticationConverter();

	@Test
	public void convertWhenDefaultGrantedAuthoritiesConverterSet() {
		Jwt jwt = jwt().claim("scope", "message:read message:write").build();

		AbstractAuthenticationToken authentication = this.jwtAuthenticationConverter.convert(jwt).block();
		Collection<GrantedAuthority> authorities = authentication.getAuthorities();

		assertThat(authorities).containsExactly(new SimpleGrantedAuthority("SCOPE_message:read"),
				new SimpleGrantedAuthority("SCOPE_message:write"));
	}

	@Test
	public void whenSettingNullGrantedAuthoritiesConverter() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(null))
				.withMessage("jwtGrantedAuthoritiesConverter cannot be null");
	}

	@Test
	public void convertWithOverriddenGrantedAuthoritiesConverter() {
		Jwt jwt = jwt().claim("scope", "message:read message:write").build();

		Converter<Jwt, Flux<GrantedAuthority>> grantedAuthoritiesConverter = token -> Flux
				.just(new SimpleGrantedAuthority("blah"));

		this.jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);

		AbstractAuthenticationToken authentication = this.jwtAuthenticationConverter.convert(jwt).block();
		Collection<GrantedAuthority> authorities = authentication.getAuthorities();

		assertThat(authorities).containsExactly(new SimpleGrantedAuthority("blah"));
	}

}
