/*
 *
 *  * Copyright 2002-2017 the original author or authors.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *      http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package org.springframework.security.config.annotation.web.reactive;

import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.web.server.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.MapUserDetailsRepository;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.web.reactive.server.WebTestClientBuilder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterChainFilter;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.FluxExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.Principal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.web.reactive.function.client.ExchangeFilterFunctions.Credentials.basicAuthenticationCredentials;
import static org.springframework.web.reactive.function.client.ExchangeFilterFunctions.basicAuthentication;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(Enclosed.class)
public class EnableWebFluxSecurityTests {
	@RunWith(SpringRunner.class)
	public static class Defaults {
		@Autowired
		WebFilterChainFilter springSecurityFilterChain;

		@Test
		public void defaultRequiresAuthentication() {
			WebTestClient client = WebTestClientBuilder.bindToWebFilters(this.springSecurityFilterChain).build();

			client.get()
				.uri("/")
				.exchange()
				.expectStatus().isUnauthorized()
				.expectBody().isEmpty();
		}

		@Test
		public void authenticateWhenBasicThenNoSession() {
			WebTestClient client = WebTestClientBuilder
				.bindToWebFilters(this.springSecurityFilterChain)
				.filter(basicAuthentication())
				.build();

			FluxExchangeResult<String> result = client.get()
				.attributes(basicAuthenticationCredentials("user", "password")).exchange()
				.expectStatus()
				.isOk()
				.returnResult(String.class);
			result.assertWithDiagnostics(() -> assertThat(result.getResponseCookies().isEmpty()));
		}

		@Test
		public void defaultPopulatesReactorContext() {
			Principal currentPrincipal = new TestingAuthenticationToken("user", "password", "ROLE_USER");
			WebTestClient client = WebTestClientBuilder.bindToWebFilters(
				(exchange, chain) ->
					chain.filter(exchange.mutate().principal(Mono.just(currentPrincipal)).build()),
				this.springSecurityFilterChain,
				(exchange,chain) ->
					Mono.subscriberContext()
						.flatMap( c -> c.<Mono<Principal>>get(Authentication.class))
						.flatMap( principal -> exchange.getResponse()
							.writeWith(Mono.just(toDataBuffer(principal.getName()))))
			).build();

			client
				.get()
				.uri("/")
				.exchange()
				.expectStatus().isOk()
				.expectBody(String.class).consumeWith( result -> assertThat(result.getResponseBody()).isEqualTo(currentPrincipal.getName()));
		}

		@Test
		public void defaultPopulatesReactorContextWhenAuthenticating() {
			WebTestClient client = WebTestClientBuilder.bindToWebFilters(
				this.springSecurityFilterChain,
				(exchange,chain) ->
					Mono.subscriberContext()
						.flatMap( c -> c.<Mono<Principal>>get(Authentication.class))
						.flatMap( principal -> exchange.getResponse()
							.writeWith(Mono.just(toDataBuffer(principal.getName()))))
			)
			.filter(basicAuthentication())
			.build();

			client
				.get()
				.uri("/")
				.attributes(basicAuthenticationCredentials("user","password"))
				.exchange()
				.expectStatus().isOk()
				.expectBody(String.class).consumeWith( result -> assertThat(result.getResponseBody()).isEqualTo("user"));
		}

		@EnableWebFluxSecurity
		static class Config {
			@Bean
			public UserDetailsRepository userDetailsRepository() {
				return new MapUserDetailsRepository(User.withUsername("user")
					.password("password")
					.roles("USER")
					.build()
				);
			}
		}
	}

	@RunWith(SpringRunner.class)
	public static class CustomPasswordEncoder {
		@Autowired
		WebFilterChainFilter springSecurityFilterChain;

		@Test
		public void passwordEncoderBeanIsUsed() {
			WebTestClient client = WebTestClientBuilder.bindToWebFilters(
				this.springSecurityFilterChain,
				(exchange,chain) ->
					Mono.subscriberContext()
						.flatMap( c -> c.<Mono<Principal>>get(Authentication.class))
						.flatMap( principal -> exchange.getResponse()
							.writeWith(Mono.just(toDataBuffer(principal.getName()))))
			)
			.filter(basicAuthentication())
			.build();

			client
				.get()
				.uri("/")
				.attributes(basicAuthenticationCredentials("user","password"))
				.exchange()
				.expectStatus().isOk()
				.expectBody(String.class).consumeWith( result -> assertThat(result.getResponseBody()).isEqualTo("user"));
		}

		@EnableWebFluxSecurity
		static class Config {
			@Bean
			public UserDetailsRepository userDetailsRepository(PasswordEncoder encoder) {
				return new MapUserDetailsRepository(User.withUsername("user")
					.password(encoder.encode("password"))
					.roles("USER")
					.build()
				);
			}

			@Bean
			public PasswordEncoder passwordEncoder() {
				return new BCryptPasswordEncoder();
			}
		}
	}


	@RunWith(SpringRunner.class)
	public static class FormLoginTests {
		@Autowired
		WebFilterChainFilter springSecurityFilterChain;
		@Test
		public void formLoginWorks() {
			WebTestClient client = WebTestClientBuilder.bindToWebFilters(
				this.springSecurityFilterChain,
				(exchange,chain) ->
					Mono.subscriberContext()
						.flatMap( c -> c.<Mono<Principal>>get(Authentication.class))
						.flatMap( principal -> exchange.getResponse()
							.writeWith(Mono.just(toDataBuffer(principal.getName()))))
			)
			.build();


			MultiValueMap<String, String> data = new LinkedMultiValueMap<>();
			data.add("username", "user");
			data.add("password", "password");
			client
				.post()
				.uri("/login")
				.body(BodyInserters.fromFormData(data))
				.exchange()
				.expectStatus().is3xxRedirection()
				.expectHeader().valueMatches("Location", "/");
		}

		@EnableWebFluxSecurity
		static class Config {
			@Bean
			public UserDetailsRepository userDetailsRepository() {
				return new MapUserDetailsRepository(User.withUsername("user")
					.password("password")
					.roles("USER")
					.build()
				);
			}
		}
	}

	@RunWith(SpringRunner.class)
	public static class MultiHttpSecurity {
		@Autowired
		WebFilterChainFilter springSecurityFilterChain;

		@Test
		public void multiWorks() {
			WebTestClient client = WebTestClientBuilder.bindToWebFilters(this.springSecurityFilterChain).build();

			client.get()
				.uri("/api/test")
				.exchange()
				.expectStatus().isUnauthorized()
				.expectBody().isEmpty();

			client.get()
				.uri("/test")
				.exchange()
				.expectStatus().isOk();
		}

		@EnableWebFluxSecurity
		static class Config {
			@Order(Ordered.HIGHEST_PRECEDENCE)
			@Bean
			public SecurityWebFilterChain apiHttpSecurity(HttpSecurity http) {
				http
					.securityMatcher(new PathPatternParserServerWebExchangeMatcher("/api/**"))
					.authorizeExchange()
						.anyExchange().denyAll();
				return http.build();
			}

			@Bean
			public SecurityWebFilterChain httpSecurity(HttpSecurity http) {
				return http.build();
			}

			@Bean
			public UserDetailsRepository userDetailsRepository() {
				return new MapUserDetailsRepository(User.withUsername("user")
					.password("password")
					.roles("USER")
					.build()
				);
			}
		}
	}

	private static DataBuffer toDataBuffer(String body) {
		DataBuffer buffer = new DefaultDataBufferFactory().allocateBuffer();
		buffer.write(body.getBytes(StandardCharsets.UTF_8));
		return buffer;
	}
}
