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

import java.util.ArrayList;
import java.util.List;

import io.rsocket.core.RSocketServer;
import io.rsocket.exceptions.ApplicationErrorException;
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
 * @author Luis Felipe Vega
 * @author Jesús Ascama Arias
 * @author Manuel Tejeda
 * @author Ebert Toribio
 */
@ContextConfiguration
@ExtendWith(SpringExtension.class)
public class RSocketMessageHandlerConnectionITests {

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

	@Test
	public void routeWhenAuthorized() {
		UsernamePasswordMetadata credentials = new UsernamePasswordMetadata("user", "password");
		// @formatter:off
		this.requester = requester().setupMetadata(credentials, UsernamePasswordMetadata.BASIC_AUTHENTICATION_MIME_TYPE)
			.connectTcp(this.server.address().getHostName(), this.server.address().getPort())
			.block();
		String hiRob = this.requester.route("secure.retrieve-mono")
			.data("rob")
			.retrieveMono(String.class)
			.block();
		// @formatter:on
		assertThat(hiRob).isEqualTo("Hi rob");
	}

	@Test
	public void routeWhenNotAuthorized() {
		UsernamePasswordMetadata credentials = new UsernamePasswordMetadata("user", "password");
		// @formatter:off
		this.requester = requester().setupMetadata(credentials, UsernamePasswordMetadata.BASIC_AUTHENTICATION_MIME_TYPE)
			.connectTcp(this.server.address().getHostName(), this.server.address().getPort())
			.block();
		assertThatExceptionOfType(ApplicationErrorException.class).isThrownBy(() -> this.requester
				.route("secure.admin.retrieve-mono")
				.data("data")
				.retrieveMono(String.class)
				.block()
		);
		// @formatter:on
	}

	@Test
	public void routeWhenStreamCredentialsAuthorized() {
		UsernamePasswordMetadata connectCredentials = new UsernamePasswordMetadata("user", "password");
		// @formatter:off
		this.requester = requester().setupMetadata(connectCredentials, UsernamePasswordMetadata.BASIC_AUTHENTICATION_MIME_TYPE)
			.connectTcp(this.server.address().getHostName(), this.server.address().getPort())
			.block();
		String hiRob = this.requester.route("secure.admin.retrieve-mono")
			.metadata(new UsernamePasswordMetadata("admin", "password"),
					UsernamePasswordMetadata.BASIC_AUTHENTICATION_MIME_TYPE)
			.data("rob")
			.retrieveMono(String.class)
			.block();
		// @formatter:on
		assertThat(hiRob).isEqualTo("Hi rob");
	}

	@Test
	public void routeWhenStreamCredentialsHaveAuthority() {
		UsernamePasswordMetadata connectCredentials = new UsernamePasswordMetadata("user", "password");
		// @formatter:off
		this.requester = requester().setupMetadata(connectCredentials, UsernamePasswordMetadata.BASIC_AUTHENTICATION_MIME_TYPE)
			.connectTcp(this.server.address().getHostName(), this.server.address().getPort())
			.block();
		String hiUser = this.requester.route("secure.authority.retrieve-mono")
			.metadata(new UsernamePasswordMetadata("admin", "password"),
					UsernamePasswordMetadata.BASIC_AUTHENTICATION_MIME_TYPE)
			.data("Felipe")
			.retrieveMono(String.class)
			.block();
		// @formatter:on
		assertThat(hiUser).isEqualTo("Hi Felipe");
	}

	@Test
	public void connectWhenNotAuthenticated() {
		// @formatter:off
		this.requester = requester().connectTcp(this.server.address().getHostName(), this.server.address().getPort())
				.block();
		assertThatExceptionOfType(Exception.class)
				.isThrownBy(() -> this.requester.route("retrieve-mono")
						.data("data")
						.retrieveMono(String.class)
						.block()
				)
				.matches((ex) -> ex instanceof RejectedSetupException
						|| ex.getClass().toString().contains("ReactiveException"));
		// @formatter:on
		// FIXME: https://github.com/rsocket/rsocket-java/issues/686
	}

	@Test
	public void connectWhenNotAuthorized() {
		UsernamePasswordMetadata credentials = new UsernamePasswordMetadata("evil", "password");
		// @formatter:off
		this.requester = requester().setupMetadata(credentials, UsernamePasswordMetadata.BASIC_AUTHENTICATION_MIME_TYPE)
				.connectTcp(this.server.address().getHostName(), this.server.address().getPort())
				.block();
		assertThatExceptionOfType(Exception.class)
				.isThrownBy(() -> this.requester.route("retrieve-mono")
						.data("data")
						.retrieveMono(String.class)
						.block()
				)
				.matches((ex) -> ex instanceof RejectedSetupException
						|| ex.getClass().toString().contains("ReactiveException"));
		// @formatter:on
		// FIXME: https://github.com/rsocket/rsocket-java/issues/686
	}

	@Test
	public void connectionDenied() {
		UsernamePasswordMetadata credentials = new UsernamePasswordMetadata("user", "password");
		// @formatter:off
		this.requester = requester().setupMetadata(credentials, UsernamePasswordMetadata.BASIC_AUTHENTICATION_MIME_TYPE)
				.connectTcp(this.server.address().getHostName(), this.server.address().getPort())
				.block();
		assertThatExceptionOfType(ApplicationErrorException.class)
				.isThrownBy(() -> this.requester.route("prohibit")
						.data("data")
						.retrieveMono(String.class)
						.block()
				);
		// @formatter:on
	}

	@Test
	public void connectWithAnyRole() {
		UsernamePasswordMetadata credentials = new UsernamePasswordMetadata("user", "password");
		// @formatter:off
		this.requester = requester().setupMetadata(credentials, UsernamePasswordMetadata.BASIC_AUTHENTICATION_MIME_TYPE)
				.connectTcp(this.server.address().getHostName(), this.server.address().getPort())
				.block();
		String hiRob = this.requester.route("anyroute")
				.data("rob")
				.retrieveMono(String.class)
				.block();
		// @formatter:on
		assertThat(hiRob).isEqualTo("Hi rob");
	}

	@Test
	public void connectWithAnyAuthority() {
		UsernamePasswordMetadata credentials = new UsernamePasswordMetadata("admin", "password");
		// @formatter:off
		this.requester = requester().setupMetadata(credentials, UsernamePasswordMetadata.BASIC_AUTHENTICATION_MIME_TYPE)
				.connectTcp(this.server.address().getHostName(), this.server.address().getPort())
				.block();
		String hiEbert = this.requester.route("management.users")
				.data("admin")
				.retrieveMono(String.class)
				.block();
		// @formatter:on
		assertThat(hiEbert).isEqualTo("Hi admin");
	}

	private RSocketRequester.Builder requester() {
		return RSocketRequester.builder().rsocketStrategies(this.handler.getRSocketStrategies());
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
			UserDetails evil = User.withDefaultPasswordEncoder()
					.username("evil")
					.password("password")
					.roles("EVIL")
					.build();
			// @formatter:on
			return new MapReactiveUserDetailsService(admin, user, evil);
		}

		@Bean
		PayloadSocketAcceptorInterceptor rsocketInterceptor(RSocketSecurity rsocket) {
			// @formatter:off
			rsocket.authorizePayload((authorize) -> authorize
					.setup().hasRole("SETUP")
					.route("secure.admin.*").hasRole("ADMIN")
					.route("secure.**").hasRole("USER")
					.route("secure.authority.*").hasAuthority("ROLE_USER")
					.route("management.*").hasAnyAuthority("ROLE_ADMIN")
					.route("prohibit").denyAll()
					.anyRequest().permitAll()
			)
			.basicAuthentication(Customizer.withDefaults());
			// @formatter:on
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
