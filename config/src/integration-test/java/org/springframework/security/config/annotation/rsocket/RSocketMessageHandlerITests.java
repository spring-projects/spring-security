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
import java.util.List;
import java.util.concurrent.TimeUnit;

import io.rsocket.core.RSocketServer;
import io.rsocket.exceptions.ApplicationErrorException;
import io.rsocket.frame.decoder.PayloadDecoder;
import io.rsocket.transport.netty.server.CloseableChannel;
import io.rsocket.transport.netty.server.TcpServerTransport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.rsocket.RSocketRequester;
import org.springframework.messaging.rsocket.RSocketStrategies;
import org.springframework.messaging.rsocket.annotation.support.RSocketMessageHandler;
import org.springframework.security.config.Customizer;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.rsocket.core.PayloadSocketAcceptorInterceptor;
import org.springframework.security.rsocket.core.SecuritySocketAcceptorInterceptor;
import org.springframework.security.rsocket.metadata.BasicAuthenticationEncoder;
import org.springframework.security.rsocket.metadata.UsernamePasswordMetadata;
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
public class RSocketMessageHandlerITests {

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
				.interceptors((registry) -> registry.forSocketAcceptor(this.interceptor)
				)
				.acceptor(this.handler.responder())
				.bind(TcpServerTransport.create("localhost", 0))
				.block();
		this.requester = RSocketRequester.builder()
				// .rsocketFactory((factory) ->
				// factory.addRequesterPlugin(payloadInterceptor))
				.rsocketStrategies(this.handler.getRSocketStrategies())
				.connectTcp("localhost", this.server.address().getPort())
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
	public void retrieveMonoWhenSecureThenDenied() throws Exception {
		String data = "rob";
		// @formatter:off
		assertThatExceptionOfType(ApplicationErrorException.class).isThrownBy(
				() -> this.requester.route("secure.retrieve-mono")
					.data(data)
					.retrieveMono(String.class)
					.block()
			)
			.withMessageContaining("Access Denied");
		// @formatter:on
		assertThat(this.controller.payloads).isEmpty();
	}

	@Test
	public void retrieveMonoWhenAuthenticationFailedThenException() throws Exception {
		String data = "rob";
		UsernamePasswordMetadata credentials = new UsernamePasswordMetadata("invalid", "password");
		// @formatter:off
		assertThatExceptionOfType(ApplicationErrorException.class)
			.isThrownBy(() -> this.requester.route("secure.retrieve-mono")
				.metadata(credentials, UsernamePasswordMetadata.BASIC_AUTHENTICATION_MIME_TYPE).data(data)
				.retrieveMono(String.class)
				.block()
			)
			.withMessageContaining("Invalid Credentials");
		// @formatter:on
		assertThat(this.controller.payloads).isEmpty();
	}

	@Test
	public void retrieveMonoWhenAuthorizedThenGranted() throws Exception {
		String data = "rob";
		UsernamePasswordMetadata credentials = new UsernamePasswordMetadata("rob", "password");
		// @formatter:off
		String hiRob = this.requester.route("secure.retrieve-mono")
			.metadata(credentials, UsernamePasswordMetadata.BASIC_AUTHENTICATION_MIME_TYPE)
			.data(data)
			.retrieveMono(String.class)
			.block();
		// @formatter:on
		assertThat(hiRob).isEqualTo("Hi rob");
		assertThat(this.controller.payloads).containsOnly(data);
	}

	@Test
	public void retrieveMonoWhenPublicThenGranted() throws Exception {
		String data = "rob";
		// @formatter:off
		String hiRob = this.requester.route("retrieve-mono")
			.data(data)
			.retrieveMono(String.class)
			.block();
		// @formatter:on
		assertThat(hiRob).isEqualTo("Hi rob");
		assertThat(this.controller.payloads).containsOnly(data);
	}

	@Test
	public void retrieveFluxWhenDataFluxAndSecureThenDenied() throws Exception {
		Flux<String> data = Flux.just("a", "b", "c");
		// @formatter:off
		assertThatExceptionOfType(ApplicationErrorException.class)
			.isThrownBy(() -> this.requester.route("secure.retrieve-flux")
				.data(data, String.class)
				.retrieveFlux(String.class)
				.collectList()
				.block()
			)
			.withMessageContaining("Access Denied");
		// @formatter:on
		assertThat(this.controller.payloads).isEmpty();
	}

	@Test
	public void retrieveFluxWhenDataFluxAndPublicThenGranted() throws Exception {
		Flux<String> data = Flux.just("a", "b", "c");
		// @formatter:off
		List<String> hi = this.requester.route("retrieve-flux")
			.data(data, String.class)
			.retrieveFlux(String.class)
			.collectList()
			.block();
		// @formatter:on
		assertThat(hi).containsOnly("hello a", "hello b", "hello c");
		assertThat(this.controller.payloads).containsOnlyElementsOf(data.collectList().block());
	}

	@Test
	public void retrieveFluxWhenDataStringAndSecureThenDenied() throws Exception {
		String data = "a";
		assertThatExceptionOfType(ApplicationErrorException.class).isThrownBy(
				() -> this.requester.route("secure.hello").data(data).retrieveFlux(String.class).collectList().block())
			.withMessageContaining("Access Denied");
		assertThat(this.controller.payloads).isEmpty();
	}

	@Test
	public void sendWhenSecureThenDenied() throws Exception {
		String data = "hi";
		// @formatter:off
		this.requester.route("secure.send")
			.data(data)
			.send()
			.block();
		// @formatter:on
		assertThat(this.controller.payloads).isEmpty();
	}

	@Test
	public void sendWhenPublicThenGranted() throws Exception {
		String data = "hi";
		// @formatter:off
		this.requester.route("send")
			.data(data)
			.send()
			.block();
		// @formatter:on
		assertThat(this.controller.awaitPayloads()).containsOnly("hi");
	}

	@Configuration
	@EnableRSocketSecurity
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
			UserDetails rossen = User.withDefaultPasswordEncoder()
					.username("rossen")
					.password("password")
					.roles("USER")
					.build();
			// @formatter:on
			return new MapReactiveUserDetailsService(rob, rossen);
		}

		@Bean
		PayloadSocketAcceptorInterceptor rsocketInterceptor(RSocketSecurity rsocket) {
			// @formatter:off
			rsocket.authorizePayload(
				(authorize) -> authorize
					.route("secure.*").authenticated()
					.anyExchange().permitAll()
				)
				.basicAuthentication(Customizer.withDefaults());
			// @formatter:on
			return rsocket.build();
		}

	}

	@Controller
	static class ServerController {

		private List<String> payloads = new ArrayList<>();

		@MessageMapping({ "secure.retrieve-mono", "retrieve-mono" })
		String retrieveMono(String payload) {
			add(payload);
			return "Hi " + payload;
		}

		@MessageMapping({ "secure.retrieve-flux", "retrieve-flux" })
		Flux<String> retrieveFlux(Flux<String> payload) {
			return payload.doOnNext(this::add).map((p) -> "hello " + p);
		}

		@MessageMapping({ "secure.send", "send" })
		Mono<Void> send(Mono<String> payload) {
			return payload.doOnNext(this::add).then(Mono.fromRunnable(this::doNotifyAll));
		}

		private synchronized void doNotifyAll() {
			this.notifyAll();
		}

		private synchronized List<String> awaitPayloads() throws InterruptedException {
			this.wait(TimeUnit.SECONDS.toMillis(1));
			return this.payloads;
		}

		private void add(String p) {
			this.payloads.add(p);
		}

	}

}
