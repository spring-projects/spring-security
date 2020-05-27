/*
 * Copyright 2002-2020 the original author or authors.
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

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.AfterClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import sample.config.SecurityConfig;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.function.client.WebClient;

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockOAuth2Client;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockOAuth2Login;

@WebFluxTest
@Import(SecurityConfig.class)
@AutoConfigureWebTestClient
@RunWith(SpringRunner.class)
public class RegisteredOAuth2AuthorizedClientControllerTests {
	private static MockWebServer web = new MockWebServer();

	@Autowired
	private WebTestClient client;

	@AfterClass
	public static void shutdown() throws Exception {
		web.shutdown();
	}

	@Test
	public void annotationExplicitWhenAuthenticatedThenUsesClientIdRegistration() throws Exception {
		web.enqueue(new MockResponse().setBody("body").setResponseCode(200));
		this.client.mutateWith(mockOAuth2Login())
				.mutateWith(mockOAuth2Client("client-id"))
				.get().uri("/annotation/explicit")
				.exchange()
				.expectStatus().isOk();
	}

	@Test
	public void annotationImplicitWhenAuthenticatedThenUsesDefaultRegistration() throws Exception {
		web.enqueue(new MockResponse().setBody("body").setResponseCode(200));
		this.client.mutateWith(mockOAuth2Login())
				.get().uri("/annotation/implicit")
				.exchange()
				.expectStatus().isOk();
	}

	@Test
	public void publicAnnotationExplicitWhenAuthenticatedThenUsesClientIdRegistration() throws Exception {
		web.enqueue(new MockResponse().setBody("body").setResponseCode(200));
		this.client.mutateWith(mockOAuth2Client("client-id"))
				.get().uri("/public/annotation/explicit")
				.exchange()
				.expectStatus().isOk();
	}

	@Test
	public void publicAnnotationImplicitWhenAuthenticatedThenUsesDefaultRegistration() throws Exception {
		web.enqueue(new MockResponse().setBody("body").setResponseCode(200));
		this.client.mutateWith(mockOAuth2Login())
				.get().uri("/public/annotation/implicit")
				.exchange()
				.expectStatus().isOk();
	}

	@TestConfiguration
	static class WebClientConfig {
		@Bean
		WebClient web() {
			return WebClient.create(web.url("/").toString());
		}
	}
}
