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

import org.junit.jupiter.api.Test;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.TestJwts;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

import static org.assertj.core.api.Assertions.assertThat;

class UserDetailsJwtPrincipalConverterTests {

	@Test
	void convertWhenUserFoundThenPrincipalIsUserDetails() {
		UserDetailsService users = (username) -> User.withDefaultPasswordEncoder()
			.username(username)
			.password("password")
			.roles("USER")
			.build();
		UserDetailsJwtPrincipalConverter principalConverter = new UserDetailsJwtPrincipalConverter(users);
		JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
		converter.setJwtPrincipalConverter(principalConverter);
		Jwt jwt = TestJwts.jwt().subject("user").build();
		OAuth2AuthenticatedPrincipal principal = (OAuth2AuthenticatedPrincipal) converter.convert(jwt).getPrincipal();
		assertThat(principal.getName()).isEqualTo("user");
		assertThat(principal.getAttributes()).containsKey("sub");
	}

}
