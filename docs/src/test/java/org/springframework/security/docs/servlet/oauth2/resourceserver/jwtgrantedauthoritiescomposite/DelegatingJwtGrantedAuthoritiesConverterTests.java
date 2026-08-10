/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.docs.servlet.oauth2.resourceserver.jwtgrantedauthoritiescomposite;

import java.util.Arrays;
import java.util.Collection;

import org.junit.jupiter.api.Test;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.TestJwts;
import org.springframework.security.oauth2.server.resource.authentication.DelegatingJwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import static org.assertj.core.api.Assertions.assertThat;

class DelegatingJwtGrantedAuthoritiesConverterTests {

	@Test
	public void convertWhenTokenHasMultipleClaimsThenAuthoritiesFromBothClaims() {
		// @formatter:off
		Jwt jwt = TestJwts.jwt()
				.claim("scp", Arrays.asList("read", "write"))
				.claim("roles", Arrays.asList("admin"))
				.build();
		// @formatter:on
		// tag::two-locations[]
		JwtGrantedAuthoritiesConverter scopesConverter = new JwtGrantedAuthoritiesConverter();

		JwtGrantedAuthoritiesConverter rolesConverter = new JwtGrantedAuthoritiesConverter();
		rolesConverter.setAuthoritiesClaimName("roles");
		rolesConverter.setAuthorityPrefix("ROLE_");

		DelegatingJwtGrantedAuthoritiesConverter converter =
				new DelegatingJwtGrantedAuthoritiesConverter(scopesConverter, rolesConverter);
		Collection<GrantedAuthority> authorities = converter.convert(jwt);
		// end::two-locations[]
		assertThat(authorities).extracting(GrantedAuthority::getAuthority)
				.containsExactlyInAnyOrder("SCOPE_read", "SCOPE_write", "ROLE_admin");
	}

}
