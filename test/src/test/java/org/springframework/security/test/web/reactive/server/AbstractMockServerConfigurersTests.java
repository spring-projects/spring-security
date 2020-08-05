/*
 * Copyright 2002-2017 the original author or authors.
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

package org.springframework.security.test.web.reactive.server;

import java.security.Principal;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 * @author Josh Cummings
 * @since 5.0
 */
abstract class AbstractMockServerConfigurersTests {

	protected PrincipalController controller = new PrincipalController();

	protected SecurityContextController securityContextController = new SecurityContextController();

	protected User.UserBuilder userBuilder = User.withUsername("user").password("password").roles("USER");

	protected void assertPrincipalCreatedFromUserDetails(Principal principal, UserDetails originalUserDetails) {
		assertThat(principal).isInstanceOf(UsernamePasswordAuthenticationToken.class);

		UsernamePasswordAuthenticationToken authentication = (UsernamePasswordAuthenticationToken) principal;
		assertThat(authentication.getCredentials()).isEqualTo(originalUserDetails.getPassword());
		assertThat(authentication.getAuthorities()).containsOnlyElementsOf(originalUserDetails.getAuthorities());

		UserDetails userDetails = (UserDetails) authentication.getPrincipal();
		assertThat(userDetails.getPassword()).isEqualTo(authentication.getCredentials());
		assertThat(authentication.getAuthorities()).containsOnlyElementsOf(userDetails.getAuthorities());
	}

	@RestController
	protected static class PrincipalController {

		volatile Principal principal;

		@RequestMapping("/**")
		public Principal get(Principal principal) {
			this.principal = principal;
			return principal;
		}

		public Principal removePrincipal() {
			Principal result = this.principal;
			this.principal = null;
			return result;
		}

		public void assertPrincipalIsEqualTo(Principal expected) {
			assertThat(this.principal).isEqualTo(expected);
			this.principal = null;
		}

	}

	@RestController
	protected static class SecurityContextController {

		volatile SecurityContext securityContext;

		@RequestMapping("/**")
		public SecurityContext get(@CurrentSecurityContext SecurityContext securityContext) {
			this.securityContext = securityContext;
			return securityContext;
		}

		public SecurityContext removeSecurityContext() {
			SecurityContext result = this.securityContext;
			this.securityContext = null;
			return result;
		}

	}

}
