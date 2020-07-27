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

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.context.ApplicationContext;
import org.springframework.core.ResolvableType;
import org.springframework.http.HttpHeaders;
import org.springframework.security.test.web.reactive.server.WebTestClientBuilder;
import org.springframework.test.web.reactive.server.FluxExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;

import static org.assertj.core.api.AssertionsForInterfaceTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(MockitoJUnitRunner.class)
public class CorsSpecTests {

	@Mock
	private CorsConfigurationSource source;

	@Mock
	private ApplicationContext context;

	ServerHttpSecurity http;

	HttpHeaders expectedHeaders = new HttpHeaders();

	Set<String> headerNamesNotPresent = new HashSet<>();

	@Before
	public void setup() {
		this.http = new TestingServerHttpSecurity().applicationContext(this.context);
		CorsConfiguration value = new CorsConfiguration();
		value.setAllowedOrigins(Arrays.asList("*"));
		given(this.source.getCorsConfiguration(any())).willReturn(value);
	}

	@Test
	public void corsWhenEnabledThenAccessControlAllowOriginAndSecurityHeaders() {
		this.http.cors().configurationSource(this.source);
		this.expectedHeaders.set("Access-Control-Allow-Origin", "*");
		this.expectedHeaders.set("X-Frame-Options", "DENY");
		assertHeaders();
	}

	@Test
	public void corsWhenEnabledInLambdaThenAccessControlAllowOriginAndSecurityHeaders() {
		this.http.cors(cors -> cors.configurationSource(this.source));
		this.expectedHeaders.set("Access-Control-Allow-Origin", "*");
		this.expectedHeaders.set("X-Frame-Options", "DENY");
		assertHeaders();
	}

	@Test
	public void corsWhenCorsConfigurationSourceBeanThenAccessControlAllowOriginAndSecurityHeaders() {
		given(this.context.getBeanNamesForType(any(ResolvableType.class))).willReturn(new String[] { "source" },
				new String[0]);
		given(this.context.getBean("source")).willReturn(this.source);
		this.expectedHeaders.set("Access-Control-Allow-Origin", "*");
		this.expectedHeaders.set("X-Frame-Options", "DENY");
		assertHeaders();
	}

	@Test
	public void corsWhenNoConfigurationSourceThenNoCorsHeaders() {
		given(this.context.getBeanNamesForType(any(ResolvableType.class))).willReturn(new String[0]);
		this.headerNamesNotPresent.add("Access-Control-Allow-Origin");
		assertHeaders();
	}

	private void assertHeaders() {
		WebTestClient client = buildClient();
		FluxExchangeResult<String> response = client.get().uri("https://example.com/")
				.headers(h -> h.setOrigin("https://origin.example.com")).exchange().returnResult(String.class);

		Map<String, List<String>> responseHeaders = response.getResponseHeaders();

		if (!this.expectedHeaders.isEmpty()) {
			assertThat(responseHeaders).describedAs(response.toString()).containsAllEntriesOf(this.expectedHeaders);
		}
		if (!this.headerNamesNotPresent.isEmpty()) {
			assertThat(responseHeaders.keySet()).doesNotContainAnyElementsOf(this.headerNamesNotPresent);
		}
	}

	private WebTestClient buildClient() {
		return WebTestClientBuilder.bindToWebFilters(this.http.build()).build();
	}

}
