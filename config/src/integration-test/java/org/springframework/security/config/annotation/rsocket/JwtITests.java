/*
 * Copyright 2002-2013 the original author or authors.
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
import java.util.Arrays;
import java.util.List;

import io.rsocket.RSocketFactory;
import io.rsocket.frame.decoder.PayloadDecoder;
import io.rsocket.metadata.WellKnownMimeType;
import io.rsocket.transport.netty.server.CloseableChannel;
import io.rsocket.transport.netty.server.TcpServerTransport;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import reactor.core.publisher.Mono;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.rsocket.RSocketRequester;
import org.springframework.messaging.rsocket.RSocketStrategies;
import org.springframework.messaging.rsocket.annotation.support.RSocketMessageHandler;
import org.springframework.security.config.Customizer;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.TestJwts;
import org.springframework.security.rsocket.core.PayloadSocketAcceptorInterceptor;
import org.springframework.security.rsocket.core.SecuritySocketAcceptorInterceptor;
import org.springframework.security.rsocket.metadata.BearerTokenAuthenticationEncoder;
import org.springframework.security.rsocket.metadata.BearerTokenMetadata;
import org.springframework.stereotype.Controller;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.MimeType;
import org.springframework.util.MimeTypeUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * @author Rob Winch
 */
@ContextConfiguration
@RunWith(SpringRunner.class)
public class JwtITests {

	@Autowired
	RSocketMessageHandler handler;

	@Autowired
	SecuritySocketAcceptorInterceptor interceptor;

	@Autowired
	ServerController controller;

	@Autowired
	ReactiveJwtDecoder decoder;

	private CloseableChannel server;

	private RSocketRequester requester;

	@Before
	public void setup() {
		this.server = RSocketFactory.receive().frameDecoder(PayloadDecoder.ZERO_COPY)
				.addSocketAcceptorPlugin(this.interceptor).acceptor(this.handler.responder())
				.transport(TcpServerTransport.create("localhost", 0)).start().block();
	}

	@After
	public void dispose() {
		this.requester.rsocket().dispose();
		this.server.dispose();
		this.controller.payloads.clear();
	}

	@Test
	public void routeWhenBearerThenAuthorized() {
		BearerTokenMetadata credentials = new BearerTokenMetadata("token");
		given(this.decoder.decode(any())).willReturn(Mono.just(jwt()));
		this.requester = requester()
				.setupMetadata(credentials.getToken(), BearerTokenMetadata.BEARER_AUTHENTICATION_MIME_TYPE)
				.connectTcp(this.server.address().getHostName(), this.server.address().getPort()).block();

		String hiRob = this.requester.route("secure.retrieve-mono").data("rob").retrieveMono(String.class).block();

		assertThat(hiRob).isEqualTo("Hi rob");
	}

	@Test
	public void routeWhenAuthenticationBearerThenAuthorized() {
		MimeType authenticationMimeType = MimeTypeUtils
				.parseMimeType(WellKnownMimeType.MESSAGE_RSOCKET_AUTHENTICATION.getString());

		BearerTokenMetadata credentials = new BearerTokenMetadata("token");
		given(this.decoder.decode(any())).willReturn(Mono.just(jwt()));
		this.requester = requester().setupMetadata(credentials, authenticationMimeType)
				.connectTcp(this.server.address().getHostName(), this.server.address().getPort()).block();

		String hiRob = this.requester.route("secure.retrieve-mono").data("rob").retrieveMono(String.class).block();

		assertThat(hiRob).isEqualTo("Hi rob");
	}

	private Jwt jwt() {
		return TestJwts.jwt().claim(IdTokenClaimNames.ISS, "https://issuer.example.com")
				.claim(IdTokenClaimNames.SUB, "rob").claim(IdTokenClaimNames.AUD, Arrays.asList("client-id")).build();
	}

	private RSocketRequester.Builder requester() {
		return RSocketRequester.builder().rsocketStrategies(this.handler.getRSocketStrategies());
	}

	@Configuration
	@EnableRSocketSecurity
	static class Config {

		@Bean
		public ServerController controller() {
			return new ServerController();
		}

		@Bean
		public RSocketMessageHandler messageHandler() {
			RSocketMessageHandler handler = new RSocketMessageHandler();
			handler.setRSocketStrategies(rsocketStrategies());
			return handler;
		}

		@Bean
		public RSocketStrategies rsocketStrategies() {
			return RSocketStrategies.builder().encoder(new BearerTokenAuthenticationEncoder()).build();
		}

		@Bean
		PayloadSocketAcceptorInterceptor rsocketInterceptor(RSocketSecurity rsocket) {
			rsocket.authorizePayload(authorize -> authorize.anyRequest().authenticated().anyExchange().permitAll())
					.jwt(Customizer.withDefaults());
			return rsocket.build();
		}

		@Bean
		ReactiveJwtDecoder jwtDecoder() {
			return mock(ReactiveJwtDecoder.class);
		}

	}

	@Controller
	static class ServerController {

		private List<String> payloads = new ArrayList<>();

		@MessageMapping("**")
		String connect(String payload) {
			return "Hi " + payload;
		}

	}

}
