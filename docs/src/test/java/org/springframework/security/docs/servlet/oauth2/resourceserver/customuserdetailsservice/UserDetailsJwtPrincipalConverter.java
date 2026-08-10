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

package org.springframework.security.docs.servlet.oauth2.resourceserver.customuserdetailsservice;

import java.util.Map;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

// tag::custom-converter[]
@Component
public final class UserDetailsJwtPrincipalConverter implements Converter<Jwt, OAuth2AuthenticatedPrincipal> {

	private final UserDetailsService users;

	public UserDetailsJwtPrincipalConverter(UserDetailsService users) {
		this.users = users;
	}

	@Override
	public OAuth2AuthenticatedPrincipal convert(Jwt jwt) {
		UserDetails user = this.users.loadUserByUsername(jwt.getSubject());
		return new JwtUser(jwt, user);
	}

	private static final class JwtUser extends User implements OAuth2AuthenticatedPrincipal {

		private final Jwt jwt;

		private JwtUser(Jwt jwt, UserDetails user) {
			super(user.getUsername(), user.getPassword(), user.isEnabled(), user.isAccountNonExpired(),
					user.isCredentialsNonExpired(), user.isAccountNonLocked(), user.getAuthorities());
			this.jwt = jwt;
		}

		@Override
		public String getName() {
			return this.jwt.getSubject();
		}

		@Override
		public Map<String, Object> getAttributes() {
			return this.jwt.getClaims();
		}

	}

}
// end::custom-converter[]
