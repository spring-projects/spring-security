/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.config.annotation.web.configuration;

import jakarta.annotation.PreDestroy;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.apache.commons.lang.StringUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.SecurityContextChangedListenerConfig;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.TestBearerTokenAuthentications;
import org.springframework.security.oauth2.server.resource.web.reactive.function.client.ServletBearerExchangeFilterFunction;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for applications of {@link SecurityReactorContextConfiguration} in resource
 * servers.
 *
 * @author Josh Cummings
 */
@ExtendWith(SpringTestContextExtension.class)
public class SecurityReactorContextConfigurationResourceServerTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	private MockMvc mockMvc;

	// gh-7418
	@Test
	public void requestWhenUsingFilterThenBearerTokenPropagated() throws Exception {
		BearerTokenAuthentication authentication = TestBearerTokenAuthentications.bearer();
		this.spring.register(BearerFilterConfig.class, WebServerConfig.class, Controller.class).autowire();
		MockHttpServletRequestBuilder authenticatedRequest = get("/token").with(authentication(authentication));
		// @formatter:off
		this.mockMvc.perform(authenticatedRequest)
				.andExpect(status().isOk())
				.andExpect(content().string("Bearer token"));
		// @formatter:on
	}

	// gh-7418
	@Test
	public void requestWhenNotUsingFilterThenBearerTokenNotPropagated() throws Exception {
		BearerTokenAuthentication authentication = TestBearerTokenAuthentications.bearer();
		this.spring.register(BearerFilterlessConfig.class, WebServerConfig.class, Controller.class).autowire();
		MockHttpServletRequestBuilder authenticatedRequest = get("/token").with(authentication(authentication));
		// @formatter:off
		this.mockMvc.perform(authenticatedRequest)
				.andExpect(status().isOk())
				.andExpect(content().string(""));
		// @formatter:on
	}

	@Test
	public void requestWhenCustomSecurityContextHolderStrategyThenUses() throws Exception {
		BearerTokenAuthentication authentication = TestBearerTokenAuthentications.bearer();
		this.spring.register(BearerFilterConfig.class, WebServerConfig.class, Controller.class,
				SecurityContextChangedListenerConfig.class).autowire();
		MockHttpServletRequestBuilder authenticatedRequest = get("/token").with(authentication(authentication));
		// @formatter:off
		this.mockMvc.perform(authenticatedRequest)
				.andExpect(status().isOk())
				.andExpect(content().string("Bearer token"));
		// @formatter:on
		SecurityContextHolderStrategy strategy = this.spring.getContext().getBean(SecurityContextHolderStrategy.class);
		verify(strategy, atLeastOnce()).getContext();
	}

	@Configuration
	@EnableWebSecurity
	static class BearerFilterConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			http.securityContext().requireExplicitSave(false);
			return http.build();
		}

		@Bean
		WebClient rest() {
			ServletBearerExchangeFilterFunction bearer = new ServletBearerExchangeFilterFunction();
			return WebClient.builder().filter(bearer).build();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class BearerFilterlessConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			return http.build();
		}

		@Bean
		WebClient rest() {
			return WebClient.create();
		}

	}

	@RestController
	static class Controller {

		private final WebClient rest;

		private final String uri;

		@Autowired
		Controller(MockWebServer server, WebClient rest) {
			this.uri = server.url("/").toString();
			this.rest = rest;
		}

		@GetMapping("/token")
		String token() {
			// @formatter:off
			return this.rest.get()
					.uri(this.uri)
					.retrieve()
					.bodyToMono(String.class)
					.flatMap((result) -> this.rest.get()
							.uri(this.uri)
							.retrieve()
							.bodyToMono(String.class)
					)
					.block();
			// @formatter:on
		}

	}

	@Configuration
	static class WebServerConfig {

		private final MockWebServer server = new MockWebServer();

		@Bean
		MockWebServer server() throws Exception {
			this.server.setDispatcher(new AuthorizationHeaderDispatcher());
			this.server.start();
			return this.server;
		}

		@PreDestroy
		void shutdown() throws Exception {
			this.server.shutdown();
		}

	}

	static class AuthorizationHeaderDispatcher extends Dispatcher {

		@Override
		public MockResponse dispatch(RecordedRequest request) {
			MockResponse response = new MockResponse().setResponseCode(200);
			String header = request.getHeader("Authorization");
			if (StringUtils.isBlank(header)) {
				return response;
			}
			return response.setBody(header);
		}

	}

}
