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
package sample;

import java.util.Map;
import java.util.function.Consumer;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockUser;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;
import static org.springframework.web.reactive.function.client.ExchangeFilterFunctions.basicAuthentication;
import static org.springframework.web.reactive.function.client.ExchangeFilterFunctions.Credentials.basicAuthenticationCredentials;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(SpringRunner.class)
@ContextConfiguration(classes = HelloWebfluxMethodApplication.class)
@ActiveProfiles("test")
public class HelloWebfluxMethodApplicationTests {
	@Autowired
	ApplicationContext context;

	WebTestClient rest;

	@Before
	public void setup() {
		this.rest = WebTestClient
			.bindToApplicationContext(this.context)
			.apply(springSecurity())
			.configureClient()
			.filter(basicAuthentication())
			.build();
	}

	@Test
	public void messageWhenNotAuthenticated() throws Exception {
		this.rest
			.get()
			.uri("/message")
			.exchange()
			.expectStatus().isUnauthorized();
	}

	// --- Basic Authentication ---

	@Test
	public void messageWhenUserThenForbidden() throws Exception {
		this.rest
			.get()
			.uri("/message")
			.attributes(robsCredentials())
			.exchange()
			.expectStatus().isEqualTo(HttpStatus.FORBIDDEN);
	}

	@Test
	public void messageWhenAdminThenOk() throws Exception {
		this.rest
			.get()
			.uri("/message")
			.attributes(adminCredentials())
			.exchange()
			.expectStatus().isOk()
			.expectBody(String.class).isEqualTo("Hello World!");
	}

	// --- WithMockUser ---

	@Test
	@WithMockUser
	public void messageWhenWithMockUserThenForbidden() throws Exception {
		this.rest
			.get()
			.uri("/message")
			.exchange()
			.expectStatus().isEqualTo(HttpStatus.FORBIDDEN);
	}

	@Test
	@WithMockUser(roles = "ADMIN")
	public void messageWhenWithMockAdminThenOk() throws Exception {
		this.rest
			.get()
			.uri("/message")
			.exchange()
			.expectStatus().isOk()
			.expectBody(String.class).isEqualTo("Hello World!");
	}

	// --- mutateWith mockUser ---

	@Test
	public void messageWhenMutateWithMockUserThenForbidden() throws Exception {
		this.rest
			.mutateWith(mockUser())
			.get()
			.uri("/message")
			.exchange()
			.expectStatus().isEqualTo(HttpStatus.FORBIDDEN);
	}

	@Test
	public void messageWhenMutateWithMockAdminThenOk() throws Exception {
		this.rest
			.mutateWith(mockUser().roles("ADMIN"))
			.get()
			.uri("/message")
			.exchange()
			.expectStatus().isOk()
			.expectBody(String.class).isEqualTo("Hello World!");
	}

	private Consumer<Map<String, Object>> robsCredentials() {
		return basicAuthenticationCredentials("rob", "rob");
	}

	private Consumer<Map<String, Object>> adminCredentials() {
		return basicAuthenticationCredentials("admin", "admin");
	}
}
