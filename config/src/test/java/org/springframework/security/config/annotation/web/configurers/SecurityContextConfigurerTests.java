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
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * Tests for {@link SecurityContextConfigurer}
 *
 * @author Rob Winch
 * @author Eleftheria Stein
 */
public class SecurityContextConfigurerTests {
	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnSecurityContextPersistenceFilter() {
		this.spring.register(ObjectPostProcessorConfig.class).autowire();

		verify(ObjectPostProcessorConfig.objectPostProcessor)
				.postProcess(any(SecurityContextPersistenceFilter.class));
	}

	@EnableWebSecurity
	static class ObjectPostProcessorConfig extends WebSecurityConfigurerAdapter {
		static ObjectPostProcessor<Object> objectPostProcessor = spy(ReflectingObjectPostProcessor.class);

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.securityContext();
			// @formatter:on
		}

		@Bean
		static ObjectPostProcessor<Object> objectPostProcessor() {
			return objectPostProcessor;
		}
	}

	static class ReflectingObjectPostProcessor implements ObjectPostProcessor<Object> {
		@Override
		public <O> O postProcess(O object) {
			return object;
		}
	}

	@Test
	public void securityContextWhenInvokedTwiceThenUsesOriginalSecurityContextRepository() throws Exception {
		this.spring.register(DuplicateDoesNotOverrideConfig.class).autowire();
		when(DuplicateDoesNotOverrideConfig.SCR.loadContext(any())).thenReturn(mock(SecurityContext.class));

		this.mvc.perform(get("/"));

		verify(DuplicateDoesNotOverrideConfig.SCR)
				.loadContext(any(HttpRequestResponseHolder.class));
	}

	@EnableWebSecurity
	static class DuplicateDoesNotOverrideConfig extends WebSecurityConfigurerAdapter {
		static SecurityContextRepository SCR = mock(SecurityContextRepository.class);

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.securityContext()
					.securityContextRepository(SCR)
					.and()
				.securityContext();
			// @formatter:on
		}
	}

	//SEC-2932
	@Test
	public void securityContextWhenSecurityContextRepositoryNotConfiguredThenDoesNotThrowException() throws Exception {
		this.spring.register(SecurityContextRepositoryDefaultsSecurityContextRepositoryConfig.class).autowire();

		this.mvc.perform(get("/"));
	}

	@Configuration
	@EnableWebSecurity
	static class SecurityContextRepositoryDefaultsSecurityContextRepositoryConfig extends WebSecurityConfigurerAdapter {
		public SecurityContextRepositoryDefaultsSecurityContextRepositoryConfig() {
			super(true);
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.addFilter(new WebAsyncManagerIntegrationFilter())
				.anonymous()
					.and()
				.securityContext()
					.and()
				.authorizeRequests()
					.anyRequest().permitAll()
					.and()
				.httpBasic();
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
				.withUser("user").password("password").roles("USER");
			// @formatter:on
		}
	}
}
