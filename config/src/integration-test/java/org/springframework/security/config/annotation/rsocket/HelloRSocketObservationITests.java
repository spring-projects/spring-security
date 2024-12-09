/*
 * Copyright 2019 the original author or authors.
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
import java.util.Iterator;
import java.util.List;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationHandler;
import io.micrometer.observation.ObservationRegistry;
import io.rsocket.core.RSocketServer;
import io.rsocket.frame.decoder.PayloadDecoder;
import io.rsocket.metadata.WellKnownMimeType;
import io.rsocket.transport.netty.server.CloseableChannel;
import io.rsocket.transport.netty.server.TcpServerTransport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.rsocket.RSocketRequester;
import org.springframework.messaging.rsocket.RSocketStrategies;
import org.springframework.messaging.rsocket.annotation.support.RSocketMessageHandler;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.rsocket.core.SecuritySocketAcceptorInterceptor;
import org.springframework.security.rsocket.metadata.SimpleAuthenticationEncoder;
import org.springframework.security.rsocket.metadata.UsernamePasswordMetadata;
import org.springframework.stereotype.Controller;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.util.MimeTypeUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * @author Rob Winch
 */
@ContextConfiguration
@ExtendWith(SpringExtension.class)
public class HelloRSocketObservationITests {

	@Autowired
	RSocketMessageHandler handler;

	@Autowired
	SecuritySocketAcceptorInterceptor interceptor;

	@Autowired
	ServerController controller;

	@Autowired
	ObservationHandler<Observation.Context> observationHandler;

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

	@Test
	public void getWhenUsingObservationRegistryThenObservesRequest() {
		UsernamePasswordMetadata credentials = new UsernamePasswordMetadata("rob", "password");
		// @formatter:off
		this.requester = RSocketRequester.builder()
				.setupMetadata(credentials, MimeTypeUtils.parseMimeType(WellKnownMimeType.MESSAGE_RSOCKET_AUTHENTICATION.getString()))
				.rsocketStrategies(this.handler.getRSocketStrategies())
				.connectTcp("localhost", this.server.address().getPort())
				.block();
		// @formatter:on
		String data = "rob";
		// @formatter:off
		this.requester.route("secure.retrieve-mono")
				.metadata(credentials, MimeTypeUtils.parseMimeType(WellKnownMimeType.MESSAGE_RSOCKET_AUTHENTICATION.getString()))
				.data(data)
				.retrieveMono(String.class)
				.block();
		// @formatter:on
		ArgumentCaptor<Observation.Context> captor = ArgumentCaptor.forClass(Observation.Context.class);
		verify(this.observationHandler, times(2)).onStart(captor.capture());
		Iterator<Observation.Context> contexts = captor.getAllValues().iterator();
		// once for setup
		assertThat(contexts.next().getName()).isEqualTo("spring.security.authentications");
		// once for request
		assertThat(contexts.next().getName()).isEqualTo("spring.security.authentications");
	}

	@Configuration
	@EnableRSocketSecurity
	static class Config {

		private ObservationHandler<Observation.Context> handler = mock(ObservationHandler.class);

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
			return RSocketStrategies.builder().encoder(new SimpleAuthenticationEncoder()).build();
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

		@Bean
		ObservationHandler<Observation.Context> observationHandler() {
			return this.handler;
		}

		@Bean
		ObservationRegistry observationRegistry() {
			given(this.handler.supportsContext(any())).willReturn(true);
			ObservationRegistry registry = ObservationRegistry.create();
			registry.observationConfig().observationHandler(this.handler);
			return registry;
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
