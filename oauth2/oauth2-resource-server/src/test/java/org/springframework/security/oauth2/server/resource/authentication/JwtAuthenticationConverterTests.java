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

import org.junit.Test;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.TestJwts;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link JwtAuthenticationConverter}
 *
 * @author Josh Cummings
 * @author Evgeniy Cheban
 */
public class JwtAuthenticationConverterTests {

	JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();

	@Test
	public void convertWhenDefaultGrantedAuthoritiesConverterSet() {
		Jwt jwt = TestJwts.jwt().claim("scope", "message:read message:write").build();
		AbstractAuthenticationToken authentication = this.jwtAuthenticationConverter.convert(jwt);
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
		Jwt jwt = TestJwts.jwt().claim("scope", "message:read message:write").build();
		Converter<Jwt, Collection<GrantedAuthority>> grantedAuthoritiesConverter = (token) -> Arrays
				.asList(new SimpleGrantedAuthority("blah"));
		this.jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
		AbstractAuthenticationToken authentication = this.jwtAuthenticationConverter.convert(jwt);
		Collection<GrantedAuthority> authorities = authentication.getAuthorities();
		assertThat(authorities).containsExactly(new SimpleGrantedAuthority("blah"));
	}

	@Test
	public void whenSettingNullPrincipalClaimName() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.jwtAuthenticationConverter.setPrincipalClaimName(null))
				.withMessage("principalClaimName cannot be empty");
	}

	@Test
	public void whenSettingEmptyPrincipalClaimName() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.jwtAuthenticationConverter.setPrincipalClaimName(""))
				.withMessage("principalClaimName cannot be empty");
	}

	@Test
	public void whenSettingBlankPrincipalClaimName() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.jwtAuthenticationConverter.setPrincipalClaimName(" "))
				.withMessage("principalClaimName cannot be empty");
	}

	@Test
	public void convertWhenPrincipalClaimNameSet() {
		this.jwtAuthenticationConverter.setPrincipalClaimName("user_id");
		Jwt jwt = TestJwts.jwt().claim("user_id", "100").build();
		AbstractAuthenticationToken authentication = this.jwtAuthenticationConverter.convert(jwt);
		assertThat(authentication.getName()).isEqualTo("100");
	}

}
