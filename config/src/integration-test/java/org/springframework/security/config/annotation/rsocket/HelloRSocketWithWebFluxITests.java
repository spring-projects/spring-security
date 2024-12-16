/*
 * Copyright 2019-2024 the original author or authors.
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

package org.springframework.security.config.annotation.rsocket;

import java.util.ArrayList;
import java.util.List;

import io.rsocket.core.RSocketServer;
import io.rsocket.exceptions.RejectedSetupException;
import io.rsocket.frame.decoder.PayloadDecoder;
import io.rsocket.transport.netty.server.CloseableChannel;
import io.rsocket.transport.netty.server.TcpServerTransport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.rsocket.RSocketRequester;
import org.springframework.messaging.rsocket.RSocketStrategies;
import org.springframework.messaging.rsocket.annotation.support.RSocketMessageHandler;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.rsocket.core.SecuritySocketAcceptorInterceptor;
import org.springframework.security.rsocket.metadata.BasicAuthenticationEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * @author Rob Winch
 */
@ContextConfiguration
@ExtendWith(SpringExtension.class)
public class HelloRSocketWithWebFluxITests {

	@Autowired
	RSocketMessageHandler handler;

	@Autowired
	SecuritySocketAcceptorInterceptor interceptor;

	@Autowired
	ServerController controller;

	private CloseableChannel server;

	private RSocketRequester requester;

	@BeforeEach
	public void setup() {
		// @formatter:off
		this.server = RSocketServer.create()
				.payloadDecoder(PayloadDecoder.ZERO_COPY)
				.interceptors((registry) ->
					registry.forSocketAcceptor(this.interceptor)
				)
				.acceptor(this.handler.responder())
				.bind(TcpServerTransport.create("localhost", 0))
				.block();
		// @formatter:on
	}

	@AfterEach
	public void dispose() {
		this.requester.rsocket().dispose();
		this.server.dispose();
		this.controller.payloads.clear();
	}

	// gh-16161
	@Test
	public void retrieveMonoWhenSecureThenDenied() {
		// @formatter:off
		this.requester = RSocketRequester.builder()
			.rsocketStrategies(this.handler.getRSocketStrategies())
			.connectTcp("localhost", this.server.address().getPort())
			.block();
		// @formatter:on
		String data = "rob";
		// @formatter:off
		assertThatExceptionOfType(Exception.class).isThrownBy(
				() -> this.requester.route("secure.retrieve-mono")
						.data(data)
						.retrieveMono(String.class)
						.block()
				)
				.matches((ex) -> ex instanceof RejectedSetupException
						|| ex.getClass().toString().contains("ReactiveException"));
		// @formatter:on
		assertThat(this.controller.payloads).isEmpty();
	}

	@Configuration
	@EnableRSocketSecurity
	@EnableWebFluxSecurity
	static class Config {

		@Bean
		ServerController controller() {
			return new ServerController();
		}

		@Bean
		RSocketMessageHandler messageHandler() {
			RSocketMessageHandler handler = new RSocketMessageHandler();
			handler.setRSocketStrategies(rsocketStrategies());
			return handler;
		}

		@Bean
		RSocketStrategies rsocketStrategies() {
			return RSocketStrategies.builder().encoder(new BasicAuthenticationEncoder()).build();
		}

		@Bean
		MapReactiveUserDetailsService uds() {
			// @formatter:off
			UserDetails rob = User.withDefaultPasswordEncoder()
					.username("rob")
					.password("password")
					.roles("USER", "ADMIN")
					.build();
			// @formatter:on
			return new MapReactiveUserDetailsService(rob);
		}

	}

	@Controller
	static class ServerController {

		private List<String> payloads = new ArrayList<>();

		@MessageMapping("**")
		String retrieveMono(String payload) {
			add(payload);
			return "Hi " + payload;
		}

		private void add(String p) {
			this.payloads.add(p);
		}

	}

}
