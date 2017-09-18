/*
 *
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.springframework.security.test.web.reactive.server;

import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.security.Principal;

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.*;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class SecurityMockServerConfigurersTests extends AbstractMockServerConfigurersTests {
	WebTestClient client = WebTestClient
		.bindToController(controller)
		.apply(springSecurity())
		.configureClient()
		.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
		.build();

	@Test
	public void mockPrincipalWhenLocalThenSuccess() {
		Principal principal = () -> "principal";
		client
			.mutateWith(mockPrincipal(principal))
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
			.get()
			.exchange()
			.expectStatus().isOk();

		controller.assertPrincipalIsEqualTo(principal);
	}

	@Test
	public void mockPrincipalWhenMultipleInvocationsThenLastInvocationWins() {
		Principal principal = () -> "principal";
		client
			.mutateWith(mockPrincipal(() -> "will be overridden"))
			.mutateWith(mockPrincipal(principal))
			.get()
			.exchange()
			.expectStatus().isOk();

		controller.assertPrincipalIsEqualTo(principal);
	}

	@Test
	public void mockAuthenticationWhenLocalThenSuccess() {
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("authentication", "secret", "ROLE_USER");
		client
			.mutateWith(mockAuthentication(authentication))
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
			.get()
			.exchange()
			.expectStatus().isOk();
		controller.assertPrincipalIsEqualTo(authentication);
	}

	@Test
	public void mockUserWhenDefaultsThenSuccess() {
		client
			.mutateWith(mockUser())
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
			.get()
			.exchange()
			.expectStatus().isOk();

		Principal actual = controller.removePrincipal();

		assertPrincipalCreatedFromUserDetails(actual, userBuilder.build());
	}

	@Test
	public void mockUserStringWhenLocalThenSuccess() {
		client
			.mutateWith(mockUser(userBuilder.build().getUsername()))
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
			.mutateWith(mockUser("admin").password("secret").roles("USER", "ADMIN"))
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
			.mutateWith(mockUser(userDetails))
			.get()
			.exchange()
			.expectStatus().isOk();

		Principal actual = controller.removePrincipal();

		assertPrincipalCreatedFromUserDetails(actual, userBuilder.build());
	}
}
