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

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.nio.charset.Charset;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.function.Consumer;

import static org.springframework.web.reactive.function.client.ExchangeFilterFunctions.Credentials.basicAuthenticationCredentials;
import static org.springframework.web.reactive.function.client.ExchangeFilterFunctions.basicAuthentication;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(SpringRunner.class)
@ContextConfiguration(classes = HelloWebfluxMethodApplication.class)
@TestPropertySource(properties = "server.port=0")
public class HelloWebfluxMethodApplicationITests {
	@Value("#{@nettyContext.address().getPort()}")
	int port;

	WebTestClient rest;

	@Before
	public void setup() {
		this.rest = WebTestClient.bindToServer()
				.filter(basicAuthentication())
				.responseTimeout(Duration.ofDays(1))
				.baseUrl("http://localhost:" + this.port)
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

	private Consumer<Map<String, Object>> robsCredentials() {
		return basicAuthenticationCredentials("rob", "rob");
	}

	private Consumer<Map<String, Object>> adminCredentials() {
		return basicAuthenticationCredentials("admin", "admin");
	}

	private String base64Encode(String value) {
		return Base64.getEncoder().encodeToString(value.getBytes(Charset.defaultCharset()));
	}
}
