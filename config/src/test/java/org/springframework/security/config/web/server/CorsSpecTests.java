/*
 * Copyright 2002-2024 the original author or authors.
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

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.context.ApplicationContext;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.http.HttpHeaders;
import org.springframework.security.test.web.reactive.server.WebTestClientBuilder;
import org.springframework.test.web.reactive.server.FluxExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

/**
 * @author Rob Winch
 * @since 5.0
 */
@ExtendWith(MockitoExtension.class)
public class CorsSpecTests {

	@Mock
	private CorsConfigurationSource source;

	private ApplicationContext context;

	ServerHttpSecurity http;

	HttpHeaders expectedHeaders = new HttpHeaders();

	Set<String> headerNamesNotPresent = new HashSet<>();

	@BeforeEach
	public void setup() {
		this.context = new GenericApplicationContext();
		((GenericApplicationContext) this.context).refresh();
		this.http = new TestingServerHttpSecurity().applicationContext(this.context);
	}

	private void givenGetCorsConfigurationWillReturnWildcard() {
		CorsConfiguration value = new CorsConfiguration();
		value.setAllowedOrigins(Arrays.asList("*"));
		given(this.source.getCorsConfiguration(any())).willReturn(value);
	}

	@Test
	public void corsWhenEnabledThenAccessControlAllowOriginAndSecurityHeaders() {
		givenGetCorsConfigurationWillReturnWildcard();
		this.http.cors().configurationSource(this.source);
		this.expectedHeaders.set("Access-Control-Allow-Origin", "*");
		this.expectedHeaders.set("X-Frame-Options", "DENY");
		assertHeaders();
	}

	@Test
	public void corsWhenEnabledInLambdaThenAccessControlAllowOriginAndSecurityHeaders() {
		givenGetCorsConfigurationWillReturnWildcard();
		this.http.cors((cors) -> cors.configurationSource(this.source));
		this.expectedHeaders.set("Access-Control-Allow-Origin", "*");
		this.expectedHeaders.set("X-Frame-Options", "DENY");
		assertHeaders();
	}

	@Test
	public void corsWhenCorsConfigurationSourceBeanThenAccessControlAllowOriginAndSecurityHeaders() {
		givenGetCorsConfigurationWillReturnWildcard();
		((GenericApplicationContext) this.context).registerBean(CorsConfigurationSource.class, () -> this.source);
		this.expectedHeaders.set("Access-Control-Allow-Origin", "*");
		this.expectedHeaders.set("X-Frame-Options", "DENY");
		assertHeaders();
	}

	@Test
	public void corsWhenNoConfigurationSourceThenNoCorsHeaders() {
		this.headerNamesNotPresent.add("Access-Control-Allow-Origin");
		assertHeaders();
	}

	private void assertHeaders() {
		WebTestClient client = buildClient();
		// @formatter:off
		FluxExchangeResult<String> response = client.get()
				.uri("https://example.com/")
				.headers((h) -> h.setOrigin("https://origin.example.com"))
				.exchange()
				.returnResult(String.class);
		// @formatter:on
		Map<String, List<String>> responseHeaders = response.getResponseHeaders();
		if (!this.expectedHeaders.isEmpty()) {
			assertThat(responseHeaders).describedAs(response.toString()).containsAllEntriesOf(this.expectedHeaders);
		}
		if (!this.headerNamesNotPresent.isEmpty()) {
			assertThat(responseHeaders.keySet()).doesNotContainAnyElementsOf(this.headerNamesNotPresent);
		}
	}

	private WebTestClient buildClient() {
		// @formatter:off
		return WebTestClientBuilder.bindToWebFilters(this.http.build())
				.build();
		// @formatter:on
	}

}
