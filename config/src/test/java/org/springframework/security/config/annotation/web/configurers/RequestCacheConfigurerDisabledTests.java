/*
 * Copyright 2002-2018 the original author or authors.
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

import javax.servlet.http.HttpSession;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link RequestCacheConfigurer#disable()}
 *
 * @author Josh Cummings
 */
public class RequestCacheConfigurerDisabledTests {
	AnnotationConfigWebApplicationContext context;

	MockHttpServletRequest request;
	MockHttpServletResponse response;
	MockFilterChain chain;

	@Autowired
	FilterChainProxy springSecurityFilterChain;

	@Before
	public void setup() {
		this.request = new MockHttpServletRequest();
		this.request.setMethod("GET");
		this.response = new MockHttpServletResponse();
		this.chain = new MockFilterChain();
	}

	@After
	public void cleanup() {
		if (this.context != null) {
			this.context.close();
		}
	}

	// gh-6102
	@Test
	public void getWhenRequestCacheIsDisabledThenExceptionTranslationFilterDoesNotStoreRequest() throws Exception {
		loadConfig(RequestCacheDisabledConfig.class);

		this.request.setServletPath("/path");
		this.request.setRequestURI("/path");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		HttpSession session = this.request.getSession();

		setup();

		this.request.setServletPath("/login");
		this.request.setMethod("POST");
		this.request.setParameter("username", "user");
		this.request.setParameter("password", "password");
		this.request.setSession(session);
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getRedirectedUrl()).isEqualTo("/");
	}

	@EnableWebSecurity
	static class RequestCacheDisabledConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			super.configure(http);
			http
				.requestCache().disable()
				.csrf().disable();
		}

		@Bean
		public UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(
				User.withUsername("user")
					.password("password")
					.roles("USER")
					.build());
		}
	}

	public void loadConfig(Class<?>... configs) {
		this.context = new AnnotationConfigWebApplicationContext();
		this.context.register(configs);
		this.context.setServletContext(new MockServletContext());
		this.context.refresh();

		this.context.getAutowireCapableBeanFactory().autowireBean(this);
	}
}
