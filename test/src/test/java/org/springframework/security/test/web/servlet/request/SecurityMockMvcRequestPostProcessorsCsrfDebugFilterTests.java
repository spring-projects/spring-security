/*
 * Copyright 2002-2016 the original author or authors.
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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.test.web.support.WebTestUtils;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.web.context.WebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

@ExtendWith(SpringExtension.class)
@ContextConfiguration
@WebAppConfiguration
public class SecurityMockMvcRequestPostProcessorsCsrfDebugFilterTests {

	@Autowired
	private WebApplicationContext wac;

	// SEC-3836
	@Test
	public void findCookieCsrfTokenRepository() {
		MockHttpServletRequest request = post("/").buildRequest(this.wac.getServletContext());
		CsrfTokenRepository csrfTokenRepository = WebTestUtils.getCsrfTokenRepository(request);
		assertThat(csrfTokenRepository).isNotNull();
		assertThat(csrfTokenRepository).isEqualTo(Config.cookieCsrfTokenRepository);
	}

	@Configuration
	@EnableWebSecurity
	static class Config {

		static CsrfTokenRepository cookieCsrfTokenRepository = new CookieCsrfTokenRepository();

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			http.csrf().csrfTokenRepository(cookieCsrfTokenRepository);
			return http.build();
		}

		@Bean
		WebSecurityCustomizer webSecurityCustomizer() {
			// Enable the DebugFilter
			return (web) -> web.debug(true);
		}

	}

}
