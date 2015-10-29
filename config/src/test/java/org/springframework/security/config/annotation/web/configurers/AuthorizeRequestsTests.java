/*
 * Copyright 2002-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation.web.configurers;

import static org.fest.assertions.Assertions.*;

import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;

/**
 * @author Rob Winch
 *
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
@WebAppConfiguration
public class AuthorizeRequestsTests {
	@Autowired
	MockHttpServletRequest request;
	@Autowired
	MockHttpServletResponse response;

	MockFilterChain chain;

	@Autowired
	FilterChainProxy springSecurityFilterChain;

	@Before
	public void setup() {
		chain = new MockFilterChain();
	}

	// SEC-3135
	@Test
	public void antMatchersMethodAndNoPatterns() throws Exception {
		request.setMethod("POST");

		springSecurityFilterChain.doFilter(request, response, chain);

		assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
	}

	@EnableWebSecurity
	static class Config extends WebSecurityConfigurerAdapter {
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.antMatchers(HttpMethod.POST).denyAll();
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
				.inMemoryAuthentication();
		}
	}
}
