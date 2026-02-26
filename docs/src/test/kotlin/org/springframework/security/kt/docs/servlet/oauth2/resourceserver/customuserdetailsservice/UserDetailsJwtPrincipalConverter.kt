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

import org.springframework.core.convert.converter.Converter
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.stereotype.Component

// tag::custom-converter[]
@Component
class UserDetailsJwtPrincipalConverter(private val users: UserDetailsService) : Converter<Jwt, OAuth2AuthenticatedPrincipal> {

	override fun convert(jwt: Jwt): OAuth2AuthenticatedPrincipal {
		val user = users.loadUserByUsername(jwt.subject)
		return JwtUser(jwt, user)
	}

	private class JwtUser(private val jwt: Jwt, user: UserDetails) :
		User(user.username, user.password, user.isEnabled, user.isAccountNonExpired, user.isCredentialsNonExpired, user.isAccountNonLocked, user.authorities),
		OAuth2AuthenticatedPrincipal {

		override fun getName(): String = jwt.subject

		override fun getAttributes(): Map<String, Any> = jwt.claims

	}

}
// end::custom-converter[]
