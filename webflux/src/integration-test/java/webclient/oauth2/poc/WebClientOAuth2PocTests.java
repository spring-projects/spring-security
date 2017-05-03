/*
 *
 *  * Copyright 2002-2017 the original author or authors.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *	  http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package webclient.oauth2.poc;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.web.reactive.function.client.ExchangeFilterFunctions.basicAuthentication;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class WebClientOAuth2PocTests {

	private MockWebServer server;

	private WebClient webClient;


	@Before
	public void setup() {
		this.server = new MockWebServer();
		String baseUrl = this.server.url("/").toString();
		this.webClient = WebClient.create(baseUrl);
	}

	@After
	public void shutdown() throws Exception {
		this.server.shutdown();
	}

	@Test
	public void httpBasicWhenNeeded() throws Exception {
		this.server.enqueue(new MockResponse().setResponseCode(401).setHeader("WWW-Authenticate", "Basic realm=\"Test\""));
		this.server.enqueue(new MockResponse().setResponseCode(200).setBody("OK"));

		ClientResponse response = this.webClient
			.filter(basicIfNeeded("rob", "rob"))
			.get()
			.uri("/")
			.exchange()
			.block();

		assertThat(response.statusCode()).isEqualTo(HttpStatus.OK);

		assertThat(this.server.takeRequest().getHeader("Authorization")).isNull();
		assertThat(this.server.takeRequest().getHeader("Authorization")).isEqualTo("Basic cm9iOnJvYg==");
	}


	@Test
	public void httpBasicWhenNotNeeded() throws Exception {
		this.server.enqueue(new MockResponse().setResponseCode(200).setBody("OK"));

		ClientResponse response = this.webClient
			.filter(basicIfNeeded("rob", "rob"))
			.get()
			.uri("/")
			.exchange()
			.block();

		assertThat(response.statusCode()).isEqualTo(HttpStatus.OK);

		assertThat(this.server.getRequestCount()).isEqualTo(1);
		assertThat(this.server.takeRequest().getHeader("Authorization")).isNull();
	}

	private ExchangeFilterFunction basicIfNeeded(String username, String password) {
		return (request, next) ->
			next.exchange(request)
				.filter( r -> !HttpStatus.UNAUTHORIZED.equals(r.statusCode()))
				.switchIfEmpty( Mono.defer(() -> {
					return basicAuthentication(username, password).filter(request, next);
				}));
	}
}
