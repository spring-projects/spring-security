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
package org.springframework.security.config.annotation.web.configurers;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests to verify that all the functionality of <request-cache> attributes is present
 *
 * @author Rob Winch
 * @author Josh Cummings
 *
 */
public class NamespaceHttpRequestCacheTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	@Test
	public void requestWhenCustomRequestCacheThenBehaviorMatchesNamespace() throws Exception {
		this.spring.register(RequestCacheRefConfig.class).autowire();
		this.mvc.perform(get("/"))
				.andExpect(status().isForbidden());
		verifyBean(RequestCache.class).saveRequest(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@EnableWebSecurity
	static class RequestCacheRefConfig extends WebSecurityConfigurerAdapter {
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.requestCache()
					.requestCache(requestCache());
		}

		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
					.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user())
					.withUser(PasswordEncodedUser.admin());
		}

		@Bean
		public RequestCache requestCache() {
			return mock(RequestCache.class);
		}
	}

	@Test
	public void requestWhenDefaultConfigurationThenUsesHttpSessionRequestCache() throws Exception {
		this.spring.register(DefaultRequestCacheRefConfig.class).autowire();

		MvcResult result = this.mvc.perform(get("/"))
				.andExpect(status().isForbidden())
				.andReturn();

		HttpSession session = result.getRequest().getSession(false);
		assertThat(session).isNotNull();
		assertThat(session.getAttribute("SPRING_SECURITY_SAVED_REQUEST")).isNotNull();
	}

	@EnableWebSecurity
	static class DefaultRequestCacheRefConfig extends WebSecurityConfigurerAdapter {
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.anyRequest().authenticated();
		}

		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user())
					.withUser(PasswordEncodedUser.admin());
		}
	}

	private <T> T verifyBean(Class<T> beanClass) {
		return verify(this.spring.getContext().getBean(beanClass));
	}
}
