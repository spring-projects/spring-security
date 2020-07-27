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

package org.springframework.security.config.web.server;

import org.apache.http.HttpHeaders;
import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.web.PortMapper;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.config.EnableWebFlux;

import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.springframework.security.config.Customizer.withDefaults;

/**
 * Tests for {@link HttpsRedirectSpecTests}
 *
 * @author Josh Cummings
 */
public class HttpsRedirectSpecTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	WebTestClient client;

	@Autowired
	public void setApplicationContext(ApplicationContext context) {
		this.client = WebTestClient.bindToApplicationContext(context).build();
	}

	@Test
	public void getWhenSecureThenDoesNotRedirect() {
		this.spring.register(RedirectToHttpConfig.class).autowire();

		this.client.get().uri("https://localhost").exchange().expectStatus().isNotFound();
	}

	@Test
	public void getWhenInsecureThenRespondsWithRedirectToSecure() {
		this.spring.register(RedirectToHttpConfig.class).autowire();

		this.client.get().uri("http://localhost").exchange().expectStatus().isFound().expectHeader()
				.valueEquals(HttpHeaders.LOCATION, "https://localhost");
	}

	@Test
	public void getWhenInsecureAndRedirectConfiguredInLambdaThenRespondsWithRedirectToSecure() {
		this.spring.register(RedirectToHttpsInLambdaConfig.class).autowire();

		this.client.get().uri("http://localhost").exchange().expectStatus().isFound().expectHeader()
				.valueEquals(HttpHeaders.LOCATION, "https://localhost");
	}

	@Test
	public void getWhenInsecureAndPathRequiresTransportSecurityThenRedirects() {
		this.spring.register(SometimesRedirectToHttpsConfig.class).autowire();

		this.client.get().uri("http://localhost:8080").exchange().expectStatus().isNotFound();

		this.client.get().uri("http://localhost:8080/secure").exchange().expectStatus().isFound().expectHeader()
				.valueEquals(HttpHeaders.LOCATION, "https://localhost:8443/secure");
	}

	@Test
	public void getWhenInsecureAndPathRequiresTransportSecurityInLambdaThenRedirects() {
		this.spring.register(SometimesRedirectToHttpsInLambdaConfig.class).autowire();

		this.client.get().uri("http://localhost:8080").exchange().expectStatus().isNotFound();

		this.client.get().uri("http://localhost:8080/secure").exchange().expectStatus().isFound().expectHeader()
				.valueEquals(HttpHeaders.LOCATION, "https://localhost:8443/secure");
	}

	@Test
	public void getWhenInsecureAndUsingCustomPortMapperThenRespondsWithRedirectToSecurePort() {
		this.spring.register(RedirectToHttpsViaCustomPortsConfig.class).autowire();

		PortMapper portMapper = this.spring.getContext().getBean(PortMapper.class);
		given(portMapper.lookupHttpsPort(4080)).willReturn(4443);

		this.client.get().uri("http://localhost:4080").exchange().expectStatus().isFound().expectHeader()
				.valueEquals(HttpHeaders.LOCATION, "https://localhost:4443");
	}

	@Test
	public void getWhenInsecureAndUsingCustomPortMapperInLambdaThenRespondsWithRedirectToSecurePort() {
		this.spring.register(RedirectToHttpsViaCustomPortsInLambdaConfig.class).autowire();

		PortMapper portMapper = this.spring.getContext().getBean(PortMapper.class);
		given(portMapper.lookupHttpsPort(4080)).willReturn(4443);

		this.client.get().uri("http://localhost:4080").exchange().expectStatus().isFound().expectHeader()
				.valueEquals(HttpHeaders.LOCATION, "https://localhost:4443");
	}

	@EnableWebFlux
	@EnableWebFluxSecurity
	static class RedirectToHttpConfig {

		@Bean
		SecurityWebFilterChain springSecurity(ServerHttpSecurity http) {
			// @formatter:off
			http
				.redirectToHttps();
			// @formatter:on

			return http.build();
		}

	}

	@EnableWebFlux
	@EnableWebFluxSecurity
	static class RedirectToHttpsInLambdaConfig {

		@Bean
		SecurityWebFilterChain springSecurity(ServerHttpSecurity http) {
			// @formatter:off
			http
				.redirectToHttps(withDefaults());
			// @formatter:on

			return http.build();
		}

	}

	@EnableWebFlux
	@EnableWebFluxSecurity
	static class SometimesRedirectToHttpsConfig {

		@Bean
		SecurityWebFilterChain springSecurity(ServerHttpSecurity http) {
			// @formatter:off
			http
				.redirectToHttps()
					.httpsRedirectWhen(new PathPatternParserServerWebExchangeMatcher("/secure"));
			// @formatter:on

			return http.build();
		}

	}

	@EnableWebFlux
	@EnableWebFluxSecurity
	static class SometimesRedirectToHttpsInLambdaConfig {

		@Bean
		SecurityWebFilterChain springSecurity(ServerHttpSecurity http) {
			// @formatter:off
			http
				.redirectToHttps(redirectToHttps ->
					redirectToHttps
						.httpsRedirectWhen(new PathPatternParserServerWebExchangeMatcher("/secure"))
				);
			// @formatter:on

			return http.build();
		}

	}

	@EnableWebFlux
	@EnableWebFluxSecurity
	static class RedirectToHttpsViaCustomPortsConfig {

		@Bean
		SecurityWebFilterChain springSecurity(ServerHttpSecurity http) {
			// @formatter:off
			http
				.redirectToHttps()
					.portMapper(portMapper());
			// @formatter:on

			return http.build();
		}

		@Bean
		public PortMapper portMapper() {
			return mock(PortMapper.class);
		}

	}

	@EnableWebFlux
	@EnableWebFluxSecurity
	static class RedirectToHttpsViaCustomPortsInLambdaConfig {

		@Bean
		SecurityWebFilterChain springSecurity(ServerHttpSecurity http) {
			// @formatter:off
			http
				.redirectToHttps(redirectToHttps ->
					redirectToHttps
						.portMapper(portMapper())
				);
			// @formatter:on

			return http.build();
		}

		@Bean
		public PortMapper portMapper() {
			return mock(PortMapper.class);
		}

	}

}
