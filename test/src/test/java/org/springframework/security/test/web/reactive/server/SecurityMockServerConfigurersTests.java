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

import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.*;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class SecurityMockServerConfigurersTests {
	PrincipalController controller = new PrincipalController();

	WebTestClient client = WebTestClient
		.bindToController(controller)
		.apply(springSecurity())
		.configureClient()
		.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
		.build();

	User.UserBuilder userBuilder = User
		.withUsername("user")
		.password("password")
		.roles("USER");

	@Test
	public void mockPrincipalWhenLocalThenSuccess() {
		Principal principal = () -> "principal";
		client
			.mutate()
			.apply(mockPrincipal(principal))
			.build()
			.get()
			.exchange()
			.expectStatus().isOk();

		controller.assertPrincipalIsEqualTo(principal);
	}

	@Test
	public void mockPrincipalWhenGlobalTheWorks() {
		Principal principal = () -> "principal";
		client = WebTestClient
			.bindToController(controller)
			.apply(springSecurity())
			.apply(mockPrincipal(principal))
			.configureClient()
			.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
			.build();

		client
			.mutate()
			.build()
			.get()
			.exchange()
			.expectStatus().isOk();

		controller.assertPrincipalIsEqualTo(principal);
	}

	@Test
	public void mockPrincipalWhenMultipleInvocationsThenLastInvocationWins() {
		Principal principal = () -> "principal";
		client
			.mutate()
			.apply(mockPrincipal(() -> "will be overridden"))
			.apply(mockPrincipal(principal))
			.build()
			.get()
			.exchange()
			.expectStatus().isOk();

		controller.assertPrincipalIsEqualTo(principal);
	}

	@Test
	public void mockAuthenticationWhenLocalThenSuccess() {
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("authentication", "secret", "ROLE_USER");
		client
			.mutate()
			.apply(mockAuthentication(authentication))
			.build()
			.get()
			.exchange()
			.expectStatus().isOk();
		controller.assertPrincipalIsEqualTo(authentication);
	}

	@Test
	public void mockAuthenticationWhenGlobalThenSuccess() {
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("authentication", "secret", "ROLE_USER");
		client = WebTestClient
			.bindToController(controller)
			.apply(springSecurity())
			.apply(mockAuthentication(authentication))
			.configureClient()
			.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
			.build();
		client
			.mutate()
			.build()
			.get()
			.exchange()
			.expectStatus().isOk();
		controller.assertPrincipalIsEqualTo(authentication);
	}

	@Test
	public void mockUserWhenDefaultsThenSuccess() {
		client
			.mutate()
			.apply(mockUser())
			.build()
			.get()
			.exchange()
			.expectStatus().isOk();

		Principal actual = controller.removePrincipal();

		assertPrincipalCreatedFromUserDetails(actual, userBuilder.build());
	}

	@Test
	public void mockUserWhenGlobalThenSuccess() {
		client = WebTestClient
			.bindToController(controller)
			.apply(springSecurity())
			.apply(mockUser())
			.configureClient()
			.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
			.build();
		client
			.mutate()
			.build()
			.get()
			.exchange()
			.expectStatus().isOk();

		Principal actual = controller.removePrincipal();

		assertPrincipalCreatedFromUserDetails(actual, userBuilder.build());
	}

	@Test
	public void mockUserStringWhenLocalThenSuccess() {
		client
			.mutate()
			.apply(mockUser(userBuilder.build().getUsername()))
			.build()
			.get()
			.exchange()
			.expectStatus().isOk();

		Principal actual = controller.removePrincipal();

		assertPrincipalCreatedFromUserDetails(actual, userBuilder.build());
	}

	@Test
	public void mockUserStringWhenCustomThenSuccess() {
		this.userBuilder = User.withUsername("admin").password("secret").roles("USER", "ADMIN");
		client
			.mutate()
			.apply(mockUser("admin").password("secret").roles("USER", "ADMIN"))
			.build()
			.get()
			.exchange()
			.expectStatus().isOk();

		Principal actual = controller.removePrincipal();

		assertPrincipalCreatedFromUserDetails(actual, userBuilder.build());
	}

	@Test
	public void mockUserUserDetailsLocalThenSuccess() {
		UserDetails userDetails = this.userBuilder.build();
		client
			.mutate()
			.apply(mockUser(userDetails))
			.build()
			.get()
			.exchange()
			.expectStatus().isOk();

		Principal actual = controller.removePrincipal();

		assertPrincipalCreatedFromUserDetails(actual, userBuilder.build());
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

	@RestController
	static class PrincipalController {
		Principal principal;

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
}
