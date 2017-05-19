/*
 *
 *  * Copyright 2002-2017 the original author or authors.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *      http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package org.springframework.security.test.web.reactive.server;

import org.assertj.core.api.AssertionsForInterfaceTypes;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.server.ServerWebExchange;

import java.security.Principal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.reactive.server.SecurityExchangeMutators.withAuthentication;
import static org.springframework.security.test.web.reactive.server.SecurityExchangeMutators.withPrincipal;
import static org.springframework.security.test.web.reactive.server.SecurityExchangeMutators.withUser;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(MockitoJUnitRunner.class)
public class SecurityExchangeMutatorsTests {
	@Mock
	Principal principal;
	@Mock
	Authentication authentication;

	ServerWebExchange exchange = MockServerHttpRequest.get("/").toExchange();

	User.UserBuilder userBuilder = User.withUsername("user").password("password").roles("USER");

	@Test
	public void withPrincipalWhenHappyPathThenSuccess() {
		assertThat(withPrincipal(principal).apply(exchange).getPrincipal().block()).isEqualTo(principal);
	}

	@Test
	public void withAuthenticationWhenHappyPathThenSuccess() {
		assertThat(withAuthentication(authentication).apply(exchange).getPrincipal().block()).isEqualTo(authentication);
	}

	@Test
	public void withUserWhenDefaultsThenSuccess() {
		Principal principal = withUser().apply(exchange).getPrincipal().block();

		assertPrincipalCreatedFromUserDetails(principal, userBuilder.build());
	}

	@Test
	public void withUserStringWhenHappyPathThenSuccess() {
		Principal principal = withUser(userBuilder.build().getUsername() ).apply(exchange).getPrincipal().block();

		assertPrincipalCreatedFromUserDetails(principal, userBuilder.build());
	}

	@Test
	public void withUserStringWhenCustomThenSuccess() {
		SecurityExchangeMutators.UserExchangeMutator withUser = withUser("admin").password("secret").roles("USER", "ADMIN");
		userBuilder = User.withUsername("admin").password("secret").roles("USER", "ADMIN");

		Principal principal = withUser.apply(exchange).getPrincipal().block();

		assertPrincipalCreatedFromUserDetails(principal, userBuilder.build() );
	}

	@Test
	public void withUserUserDetailsWhenHappyPathThenSuccess() {
		Principal principal = withUser(userBuilder.build()).apply(exchange).getPrincipal().block();

		assertPrincipalCreatedFromUserDetails(principal, userBuilder.build());
	}

	private void assertPrincipalCreatedFromUserDetails(Principal principal, UserDetails originalUserDetails) {
		assertThat(principal).isInstanceOf(UsernamePasswordAuthenticationToken.class);

		UsernamePasswordAuthenticationToken authentication = (UsernamePasswordAuthenticationToken) principal;
		assertThat(authentication.getCredentials()).isEqualTo(originalUserDetails.getPassword());
		assertThat(authentication.getAuthorities()).containsOnlyElementsOf(originalUserDetails.getAuthorities());

		UserDetails userDetails = (UserDetails) authentication.getPrincipal();
		assertThat(userDetails.getPassword()).isEqualTo(authentication.getCredentials());
		assertThat(authentication.getAuthorities()).containsOnlyElementsOf(userDetails.getAuthorities());
	}
}
