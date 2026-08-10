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

package org.springframework.security.kt.docs.servlet.oauth2.resourceserver.jwtgrantedauthoritiescomposite

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.tuple
import org.junit.jupiter.api.Test
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.oauth2.jwt.TestJwts
import org.springframework.security.oauth2.server.resource.authentication.DelegatingJwtGrantedAuthoritiesConverter
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter

class DelegatingJwtGrantedAuthoritiesConverterTests {

	@Test
	fun convertWhenTokenHasMultipleClaimsThenAuthoritiesFromBothClaims() {
		// @formatter:off
		val jwt = TestJwts.jwt()
				.claim("scp", listOf("read", "write"))
				.claim("roles", listOf("admin"))
				.build()
		// @formatter:on
		// tag::two-locations[]
		val scopesConverter = JwtGrantedAuthoritiesConverter()

		val rolesConverter = JwtGrantedAuthoritiesConverter()
		rolesConverter.setAuthoritiesClaimName("roles")
		rolesConverter.setAuthorityPrefix("ROLE_")

		val converter = DelegatingJwtGrantedAuthoritiesConverter(scopesConverter, rolesConverter)
		val authorities = converter.convert(jwt)
		// end::two-locations[]
		assertThat(authorities).extracting(GrantedAuthority::getAuthority)
				.containsExactlyInAnyOrder(tuple("SCOPE_read"), tuple("SCOPE_write"), tuple("ROLE_admin"))
	}

}
