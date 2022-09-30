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

package org.springframework.security.config.annotation.web.configurers;

import java.util.Collections;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.web.PortMapperImpl;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;

/**
 * @author Rob Winch
 * @author Josh Cummings
 */
@ExtendWith(SpringTestContextExtension.class)
public class PortMapperConfigurerTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	private MockMvc mockMvc;

	@Test
	public void requestWhenPortMapperTwiceInvokedThenDoesNotOverride() throws Exception {
		this.spring.register(InvokeTwiceDoesNotOverride.class).autowire();
		this.mockMvc.perform(get("http://localhost:543")).andExpect(redirectedUrl("https://localhost:123"));
	}

	@Test
	public void requestWhenPortMapperHttpMapsToInLambdaThenRedirectsToHttpsPort() throws Exception {
		this.spring.register(HttpMapsToInLambdaConfig.class).autowire();
		this.mockMvc.perform(get("http://localhost:543")).andExpect(redirectedUrl("https://localhost:123"));
	}

	@Test
	public void requestWhenCustomPortMapperInLambdaThenRedirectsToHttpsPort() throws Exception {
		this.spring.register(CustomPortMapperInLambdaConfig.class).autowire();
		this.mockMvc.perform(get("http://localhost:543")).andExpect(redirectedUrl("https://localhost:123"));
	}

	@Configuration
	@EnableWebSecurity
	static class InvokeTwiceDoesNotOverride {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.requiresChannel()
					.anyRequest().requiresSecure()
					.and()
				.portMapper()
					.http(543).mapsTo(123)
					.and()
				.portMapper();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class HttpMapsToInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.requiresChannel((requiresChannel) ->
					requiresChannel
					.anyRequest().requiresSecure()
				)
				.portMapper((portMapper) ->
					portMapper
						.http(543).mapsTo(123)
				);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CustomPortMapperInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			PortMapperImpl customPortMapper = new PortMapperImpl();
			customPortMapper.setPortMappings(Collections.singletonMap("543", "123"));
			// @formatter:off
			http
				.requiresChannel((requiresChannel) ->
					requiresChannel
						.anyRequest().requiresSecure()
				)
				.portMapper((portMapper) ->
					portMapper
						.portMapper(customPortMapper)
				);
			return http.build();
			// @formatter:on
		}

	}

}
