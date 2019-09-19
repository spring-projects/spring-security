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
package org.springframework.security.config.annotation.rsocket;

import io.rsocket.RSocketFactory;
import io.rsocket.exceptions.ApplicationErrorException;
import io.rsocket.frame.decoder.PayloadDecoder;
import io.rsocket.transport.netty.server.CloseableChannel;
import io.rsocket.transport.netty.server.TcpServerTransport;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
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
import org.springframework.test.context.junit4.SpringRunner;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * @author Rob Winch
 * @author Ebert Toribio
 */
@ContextConfiguration
@RunWith(SpringRunner.class)
public class RSocketMessageHandlerConnectionITests {
	@Autowired
	RSocketMessageHandler handler;

	@Autowired
	SecuritySocketAcceptorInterceptor interceptor;

	@Autowired
	ServerController controller;

	private CloseableChannel server;

	private RSocketRequester requester;

	@Before
	public void setup() {
		this.server = RSocketFactory.receive()
				.frameDecoder(PayloadDecoder.ZERO_COPY)
				.addSocketAcceptorPlugin(this.interceptor)
				.acceptor(this.handler.responder())
				.transport(TcpServerTransport.create("localhost", 0))
				.start()
				.block();
	}

	@After
	public void dispose() {
		this.requester.rsocket().dispose();
		this.server.dispose();
		this.controller.payloads.clear();
	}

	@Test
	public void routeWhenAuthorized() {
		UsernamePasswordMetadata credentials =
				new UsernamePasswordMetadata("user", "password");
		this.requester = requester()
				.setupMetadata(credentials, UsernamePasswordMetadata.BASIC_AUTHENTICATION_MIME_TYPE)
				.connectTcp(this.server.address().getHostName(), this.server.address().getPort())
				.block();

		String hiRob = this.requester.route("secure.retrieve-mono")
				.data("rob")
				.retrieveMono(String.class)
				.block();

		assertThat(hiRob).isEqualTo("Hi rob");
	}

	@Test
	public void routeWhenNotAuthorized() {
		UsernamePasswordMetadata credentials = new UsernamePasswordMetadata("user", "password");
		this.requester = requester()
				.setupMetadata(credentials, UsernamePasswordMetadata.BASIC_AUTHENTICATION_MIME_TYPE)
				.connectTcp(this.server.address().getHostName(), this.server.address().getPort())
				.block();

		assertThatCode(() -> this.requester.route("secure.admin.retrieve-mono")
				.data("data")
				.retrieveMono(String.class)
				.block())
			.isInstanceOf(ApplicationErrorException.class);
	}

	@Test
	public void routeWhenStreamCredentialsAuthorized() {
		UsernamePasswordMetadata connectCredentials = new UsernamePasswordMetadata("user", "password");
		this.requester = requester()
				.setupMetadata(connectCredentials, UsernamePasswordMetadata.BASIC_AUTHENTICATION_MIME_TYPE)
				.connectTcp(this.server.address().getHostName(), this.server.address().getPort())
				.block();

		String hiRob = this.requester.route("secure.admin.retrieve-mono")
				.metadata(new UsernamePasswordMetadata("admin", "password"), UsernamePasswordMetadata.BASIC_AUTHENTICATION_MIME_TYPE)
				.data("rob")
				.retrieveMono(String.class)
				.block();

		assertThat(hiRob).isEqualTo("Hi rob");
	}

	@Test
	public void connectWhenNotAuthenticated() {
		this.requester = requester()
				.connectTcp(this.server.address().getHostName(), this.server.address().getPort())
				.block();

		assertThatCode(() -> this.requester.route("retrieve-mono")
				.data("data")
				.retrieveMono(String.class)
				.block())
				.isNotNull();
		// FIXME: https://github.com/rsocket/rsocket-java/issues/686
		//			.isInstanceOf(RejectedSetupException.class);
	}

	@Test
	public void connectWhenNotAuthorized() {
		UsernamePasswordMetadata credentials = new UsernamePasswordMetadata("evil", "password");
		this.requester = requester()
				.setupMetadata(credentials, UsernamePasswordMetadata.BASIC_AUTHENTICATION_MIME_TYPE)
				.connectTcp(this.server.address().getHostName(), this.server.address().getPort())
				.block();

		assertThatCode(() -> this.requester.route("retrieve-mono")
				.data("data")
				.retrieveMono(String.class)
				.block())
			.isNotNull();
//		 FIXME: https://github.com/rsocket/rsocket-java/issues/686
//			.isInstanceOf(RejectedSetupException.class);
	}

	@Test
	public void connectWithAnyAuthority() {
		UsernamePasswordMetadata credentials =
				new UsernamePasswordMetadata("ebert", "ebert");
		this.requester = requester()
				.setupMetadata(credentials, UsernamePasswordMetadata.BASIC_AUTHENTICATION_MIME_TYPE)
				.connectTcp(this.server.address().getHostName(), this.server.address().getPort())
				.block();

		String hiEbert = this.requester.route("management.users")
				.data("ebert")
				.retrieveMono(String.class)
				.block();

		assertThat(hiEbert).isEqualTo("Hi ebert");
	}

	private RSocketRequester.Builder requester() {
		return RSocketRequester.builder()
				.rsocketStrategies(this.handler.getRSocketStrategies());
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
			return RSocketStrategies.builder()
					.encoder(new BasicAuthenticationEncoder())
					.build();
		}

		@Bean
		MapReactiveUserDetailsService uds() {
			UserDetails admin = User.withDefaultPasswordEncoder()
					.username("admin")
					.password("password")
					.roles("USER", "ADMIN", "SETUP")
					.build();
			UserDetails user = User.withDefaultPasswordEncoder()
					.username("user")
					.password("password")
					.roles("USER", "SETUP")
					.build();
			UserDetails manager = User.withDefaultPasswordEncoder()
					.username("ebert")
					.password("ebert")
					.roles("SETUP", "MANAGER")
					.build();

			UserDetails evil = User.withDefaultPasswordEncoder()
					.username("evil")
					.password("password")
					.roles("EVIL")
					.build();
			return new MapReactiveUserDetailsService(admin, user, manager, evil);
		}

		@Bean
		PayloadSocketAcceptorInterceptor rsocketInterceptor(RSocketSecurity rsocket) {
			rsocket
				.authorizePayload(authorize ->
					authorize
						.setup().hasRole("SETUP")
						.route("secure.admin.*").hasRole("ADMIN")
						.route("secure.**").hasRole("USER")
						.route("management.*").hasAnyAuthority("ROLE_MANAGER")
						.anyRequest().permitAll()
				)
				.basicAuthentication(Customizer.withDefaults());
			return rsocket.build();
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
