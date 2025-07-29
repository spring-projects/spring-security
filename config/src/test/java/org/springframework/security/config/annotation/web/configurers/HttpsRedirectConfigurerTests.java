/*
 * Copyright 2004-present the original author or authors.
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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.config.web.PathPatternRequestMatcherBuilderFactoryBean;
import org.springframework.security.web.PortMapper;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link HttpsRedirectConfigurerTests}
 *
 * @author Josh Cummings
 */
@ExtendWith(SpringTestContextExtension.class)
public class HttpsRedirectConfigurerTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	@Test
	public void getWhenSecureThenDoesNotRedirect() throws Exception {
		this.spring.register(RedirectToHttpConfig.class).autowire();
		// @formatter:off
		this.mvc.perform(get("https://localhost"))
				.andExpect(status().isNotFound());
		// @formatter:on
	}

	@Test
	public void getWhenInsecureThenRespondsWithRedirectToSecure() throws Exception {
		this.spring.register(RedirectToHttpConfig.class).autowire();
		// @formatter:off
		this.mvc.perform(get("http://localhost"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("https://localhost"));
		// @formatter:on
	}

	@Test
	public void getWhenInsecureAndPathRequiresTransportSecurityThenRedirects() throws Exception {
		this.spring.register(SometimesRedirectToHttpsConfig.class, UsePathPatternConfig.class).autowire();
		// @formatter:off
		this.mvc.perform(get("http://localhost:8080"))
				.andExpect(status().isNotFound());
		this.mvc.perform(get("http://localhost:8080/secure"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("https://localhost:8443/secure"));
		// @formatter:on
	}

	@Test
	public void getWhenInsecureAndUsingCustomPortMapperThenRespondsWithRedirectToSecurePort() throws Exception {
		this.spring.register(RedirectToHttpsViaCustomPortsConfig.class).autowire();
		PortMapper portMapper = this.spring.getContext().getBean(PortMapper.class);
		given(portMapper.lookupHttpsPort(4080)).willReturn(4443);
		// @formatter:off
		this.mvc.perform(get("http://localhost:4080"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("https://localhost:4443"));
		// @formatter:on
	}

	@Configuration
	@EnableWebMvc
	@EnableWebSecurity
	static class RedirectToHttpConfig {

		@Bean
		SecurityFilterChain springSecurity(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.redirectToHttps(withDefaults());
			// @formatter:on
			return http.build();
		}

	}

	@Configuration
	@EnableWebMvc
	@EnableWebSecurity
	static class SometimesRedirectToHttpsConfig {

		@Bean
		SecurityFilterChain springSecurity(HttpSecurity http, PathPatternRequestMatcher.Builder path) throws Exception {
			// @formatter:off
			http
				.redirectToHttps((https) -> https.requestMatchers(path.matcher("/secure")));
			// @formatter:on
			return http.build();
		}

		@Bean
		PathPatternRequestMatcherBuilderFactoryBean requestMatcherBuilder() {
			return new PathPatternRequestMatcherBuilderFactoryBean();
		}

	}

	@Configuration
	@EnableWebMvc
	@EnableWebSecurity
	static class RedirectToHttpsViaCustomPortsConfig {

		@Bean
		SecurityFilterChain springSecurity(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.portMapper((p) -> p.portMapper(portMapper()))
				.redirectToHttps(withDefaults());

			// @formatter:on
			return http.build();
		}

		@Bean
		PortMapper portMapper() {
			return mock(PortMapper.class);
		}

	}

	@Configuration
	static class UsePathPatternConfig {

		@Bean
		PathPatternRequestMatcherBuilderFactoryBean requestMatcherBuilder() {
			return new PathPatternRequestMatcherBuilderFactoryBean();
		}

	}

}
