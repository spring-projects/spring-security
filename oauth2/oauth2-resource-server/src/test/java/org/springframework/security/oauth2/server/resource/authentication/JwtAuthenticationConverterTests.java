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

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.junit.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Tests for {@link JwtAuthenticationConverter}
 *
 * @author Josh Cummings
 */
public class JwtAuthenticationConverterTests {
	private static final Set<GrantedAuthority> FULL_AUTHORITIES = new HashSet<>(
			Arrays.asList(new SimpleGrantedAuthority("message:read"), new SimpleGrantedAuthority("message:write")));
	JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter(jwt -> FULL_AUTHORITIES);

	@Test
	public void convertWhenDefaultGrantedAuthoritiesConverterSet() {
		final Jwt jwt = this.jwt(Collections.singletonMap("scope", "message:read message:write"));

		final AbstractAuthenticationToken authentication = this.jwtAuthenticationConverter.convert(jwt);
		final Collection<GrantedAuthority> authorities = authentication.getAuthorities();

		assertThat(authorities).containsExactly(
				new SimpleGrantedAuthority("message:read"),
				new SimpleGrantedAuthority("message:write"));
	}

	@Test
	public void convertWithOverriddenGrantedAuthoritiesConverter() {
		final Jwt jwt = this.jwt(Collections.singletonMap("scope", "message:read message:write"));

		this.jwtAuthenticationConverter =
				new JwtAuthenticationConverter(token -> Arrays.asList(new SimpleGrantedAuthority("blah")));

		final AbstractAuthenticationToken authentication = this.jwtAuthenticationConverter.convert(jwt);
		final Collection<GrantedAuthority> authorities = authentication.getAuthorities();

		assertThat(authorities).containsExactly(new SimpleGrantedAuthority("blah"));
	}

	private Jwt jwt(final Map<String, Object> claims) {
		final Map<String, Object> headers = new HashMap<>();
		headers.put("alg", JwsAlgorithms.RS256);

		return new Jwt("token", Instant.now(), Instant.now().plusSeconds(3600), headers, claims);
	}
}
