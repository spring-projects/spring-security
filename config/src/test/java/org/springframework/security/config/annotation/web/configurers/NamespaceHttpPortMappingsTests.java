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

import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;

/**
 * Tests to verify that all the functionality of &lt;port-mappings&gt; attributes is
 * present
 *
 * @author Rob Winch
 * @author Josh Cummings
 *
 */
public class NamespaceHttpPortMappingsTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	@Test
	public void portMappingWhenRequestRequiresChannelThenBehaviorMatchesNamespace() throws Exception {
		this.spring.register(HttpInterceptUrlWithPortMapperConfig.class).autowire();

		this.mvc.perform(get("http://localhost:9080/login")).andExpect(redirectedUrl("https://localhost:9443/login"));

		this.mvc.perform(get("http://localhost:9080/secured/a"))
				.andExpect(redirectedUrl("https://localhost:9443/secured/a"));

		this.mvc.perform(get("https://localhost:9443/user")).andExpect(redirectedUrl("http://localhost:9080/user"));
	}

	@EnableWebSecurity
	static class HttpInterceptUrlWithPortMapperConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.portMapper()
					.http(9080).mapsTo(9443)
					.and()
				.requiresChannel()
					.antMatchers("/login", "/secured/**").requiresSecure()
					.anyRequest().requiresInsecure();
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser("user").password("password").roles("USER").and()
					.withUser("admin").password("password").roles("USER", "ADMIN");
			// @formatter:on
		}

	}

}
