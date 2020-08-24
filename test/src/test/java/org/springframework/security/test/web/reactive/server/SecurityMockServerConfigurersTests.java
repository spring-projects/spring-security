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

import org.junit.Test;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.server.context.SecurityContextServerWebExchangeWebFilter;
import org.springframework.security.web.server.csrf.CsrfWebFilter;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class SecurityMockServerConfigurersTests extends AbstractMockServerConfigurersTests {

	WebTestClient client = WebTestClient.bindToController(this.controller)
			.webFilter(new CsrfWebFilter(), new SecurityContextServerWebExchangeWebFilter())
			.apply(SecurityMockServerConfigurers.springSecurity()).configureClient()
			.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE).build();

	@Test
	public void mockAuthenticationWhenLocalThenSuccess() {
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("authentication", "secret",
				"ROLE_USER");
		this.client.mutateWith(SecurityMockServerConfigurers.mockAuthentication(authentication)).get().exchange()
				.expectStatus().isOk();
		this.controller.assertPrincipalIsEqualTo(authentication);
	}

	@Test
	public void mockAuthenticationWhenGlobalThenSuccess() {
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("authentication", "secret",
				"ROLE_USER");
		this.client = WebTestClient.bindToController(this.controller)
				.webFilter(new SecurityContextServerWebExchangeWebFilter())
				.apply(SecurityMockServerConfigurers.springSecurity())
				.apply(SecurityMockServerConfigurers.mockAuthentication(authentication)).configureClient()
				.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE).build();
		this.client.get().exchange().expectStatus().isOk();
		this.controller.assertPrincipalIsEqualTo(authentication);
	}

	@Test
	public void mockUserWhenDefaultsThenSuccess() {
		this.client.mutateWith(SecurityMockServerConfigurers.mockUser()).get().exchange().expectStatus().isOk();
		Principal actual = this.controller.removePrincipal();
		assertPrincipalCreatedFromUserDetails(actual, this.userBuilder.build());
	}

	@Test
	public void mockUserWhenGlobalThenSuccess() {
		this.client = WebTestClient.bindToController(this.controller)
				.webFilter(new SecurityContextServerWebExchangeWebFilter())
				.apply(SecurityMockServerConfigurers.springSecurity()).apply(SecurityMockServerConfigurers.mockUser())
				.configureClient().defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE).build();
		this.client.get().exchange().expectStatus().isOk();
		Principal actual = this.controller.removePrincipal();
		assertPrincipalCreatedFromUserDetails(actual, this.userBuilder.build());
	}

	@Test
	public void mockUserStringWhenLocalThenSuccess() {
		this.client.mutateWith(SecurityMockServerConfigurers.mockUser(this.userBuilder.build().getUsername())).get()
				.exchange().expectStatus().isOk();
		Principal actual = this.controller.removePrincipal();
		assertPrincipalCreatedFromUserDetails(actual, this.userBuilder.build());
	}

	@Test
	public void mockUserStringWhenCustomThenSuccess() {
		this.userBuilder = User.withUsername("admin").password("secret").roles("USER", "ADMIN");
		this.client
				.mutateWith(SecurityMockServerConfigurers.mockUser("admin").password("secret").roles("USER", "ADMIN"))
				.get().exchange().expectStatus().isOk();
		Principal actual = this.controller.removePrincipal();
		assertPrincipalCreatedFromUserDetails(actual, this.userBuilder.build());
	}

	@Test
	public void mockUserUserDetailsLocalThenSuccess() {
		UserDetails userDetails = this.userBuilder.build();
		this.client.mutateWith(SecurityMockServerConfigurers.mockUser(userDetails)).get().exchange().expectStatus()
				.isOk();
		Principal actual = this.controller.removePrincipal();
		assertPrincipalCreatedFromUserDetails(actual, this.userBuilder.build());
	}

	@Test
	public void csrfWhenMutateWithThenDisablesCsrf() {
		this.client.post().exchange().expectStatus().isEqualTo(HttpStatus.FORBIDDEN).expectBody()
				.consumeWith((b) -> assertThat(new String(b.getResponseBody())).contains("CSRF"));
		this.client.mutateWith(SecurityMockServerConfigurers.csrf()).post().exchange().expectStatus().isOk();
	}

	@Test
	public void csrfWhenGlobalThenDisablesCsrf() {
		this.client = WebTestClient.bindToController(this.controller).webFilter(new CsrfWebFilter())
				.apply(SecurityMockServerConfigurers.springSecurity()).apply(SecurityMockServerConfigurers.csrf())
				.configureClient().build();
		this.client.get().exchange().expectStatus().isOk();
	}

}
