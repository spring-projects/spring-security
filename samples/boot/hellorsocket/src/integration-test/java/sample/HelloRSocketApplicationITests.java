/*
 * Copyright 2002-2019 the original author or authors.
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

import org.junit.Ignore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.rsocket.context.LocalRSocketServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.messaging.rsocket.RSocketRequester;
import org.springframework.security.rsocket.metadata.BasicAuthenticationEncoder;
import org.springframework.security.rsocket.metadata.UsernamePasswordMetadata;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import org.junit.Test;
import org.junit.runner.RunWith;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.rsocket.metadata.UsernamePasswordMetadata.BASIC_AUTHENTICATION_MIME_TYPE;

/**
 * @author Rob Winch
 * @author Eddú Meléndez
 * @since 5.0
 */
@RunWith(SpringRunner.class)
@TestPropertySource(properties = "spring.rsocket.server.port=0")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Ignore
public class HelloRSocketApplicationITests {

	@Autowired
	RSocketRequester.Builder requester;

	@LocalRSocketServerPort
	int port;

	@Test
	public void messageWhenAuthenticatedThenSuccess() {
		UsernamePasswordMetadata credentials = new UsernamePasswordMetadata("user", "password");
		RSocketRequester requester = this.requester
				.rsocketStrategies(builder -> builder.encoder(new BasicAuthenticationEncoder()))
				.setupMetadata(credentials, BASIC_AUTHENTICATION_MIME_TYPE)
				.connectTcp("localhost", this.port)
				.block();

		String message = requester.route("message")
				.data(Mono.empty())
				.retrieveMono(String.class)
				.block();

		assertThat(message).isEqualTo("Hello");
	}

	@Test
	public void messageWhenNotAuthenticatedThenError() {
		RSocketRequester requester = this.requester
				.connectTcp("localhost", this.port)
				.block();

		assertThatThrownBy(() -> requester.route("message")
				.data(Mono.empty())
				.retrieveMono(String.class)
				.block())
				.isNotNull();
	}

}
