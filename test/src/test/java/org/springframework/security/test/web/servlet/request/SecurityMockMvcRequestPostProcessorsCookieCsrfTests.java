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

package org.springframework.security.test.web.servlet.request;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessorsCookieCsrfTests.Config.TheController;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestHandler;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@ContextConfiguration
@WebAppConfiguration
public class SecurityMockMvcRequestPostProcessorsCookieCsrfTests {

	@Autowired
	WebApplicationContext wac;

	@Autowired
	TheController controller;

	@Autowired
	FilterChainProxy springSecurityFilterChain;

	MockMvc mockMvc;

	@BeforeEach
	public void setup() {
		// @formatter:off
		this.mockMvc = MockMvcBuilders
			.webAppContextSetup(this.wac)
			.apply(springSecurity())
			.build();
		// @formatter:on
	}

	// gh-12774
	@Test
	public void csrfWithCookie() throws Exception {
		// @formatter:off
		this.mockMvc = MockMvcBuilders
				.standaloneSetup(this.controller)
				.apply(springSecurity(this.springSecurityFilterChain))
				.build();
		this.mockMvc.perform(post("/").with(csrf()))
			.andExpect(status().is2xxSuccessful())
			.andExpect(csrfAsParam());
		// @formatter:on
	}

	public static ResultMatcher csrfAsParam() {
		return new CsrfParamResultMatcher();
	}

	static class CsrfParamResultMatcher implements ResultMatcher {

		@Override
		public void match(MvcResult result) {
			MockHttpServletRequest request = result.getRequest();
			assertThat(request.getParameter("_csrf")).isNotNull();
			assertThat(request.getHeader("X-CSRF-TOKEN")).isNull();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class Config {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// Configured as documented here:
			// https://docs.spring.io/spring-security/reference/5.8/migration/servlet/exploits.html#servlet-csrf-breach-opt-out
			CookieCsrfTokenRepository tokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
			XorCsrfTokenRequestAttributeHandler delegate = new XorCsrfTokenRequestAttributeHandler();
			delegate.setCsrfRequestAttributeName("_csrf");
			CsrfTokenRequestHandler requestHandler = delegate::handle;
			http
					.csrf((csrf) -> csrf
							.csrfTokenRepository(tokenRepository)
							.csrfTokenRequestHandler(requestHandler)
					);
			return http.build();
		}

		@RestController
		static class TheController {

			@RequestMapping("/")
			String index() {
				return "Hi";
			}

		}

	}

}
