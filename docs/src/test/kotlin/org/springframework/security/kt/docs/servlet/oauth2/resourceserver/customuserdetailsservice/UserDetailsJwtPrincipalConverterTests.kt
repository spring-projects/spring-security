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

package org.springframework.security.kt.docs.servlet.oauth2.resourceserver.customuserdetailsservice

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.security.core.userdetails.User
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal
import org.springframework.security.oauth2.jwt.TestJwts
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter

class UserDetailsJwtPrincipalConverterTests {

	@Test
	fun convertWhenUserFoundThenPrincipalIsUserDetails() {
		@Suppress("DEPRECATION")
		val users = { username: String ->
			User.withDefaultPasswordEncoder()
				.username(username)
				.password("password")
				.roles("USER")
				.build()
		}
		val principalConverter = UserDetailsJwtPrincipalConverter(users)
		val converter = JwtAuthenticationConverter()
		converter.setJwtPrincipalConverter(principalConverter)
		val jwt = TestJwts.jwt().subject("user").build()
		val principal = converter.convert(jwt).principal as OAuth2AuthenticatedPrincipal
		assertThat(principal.name).isEqualTo("user")
		assertThat(principal.attributes).containsKey("sub")
	}

}
