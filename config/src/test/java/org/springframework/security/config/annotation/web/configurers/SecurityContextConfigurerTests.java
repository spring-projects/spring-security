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

import javax.servlet.http.HttpSession;

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
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
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
		verify(ObjectPostProcessorConfig.objectPostProcessor).postProcess(any(SecurityContextPersistenceFilter.class));
	}

	@Test
	public void securityContextWhenInvokedTwiceThenUsesOriginalSecurityContextRepository() throws Exception {
		this.spring.register(DuplicateDoesNotOverrideConfig.class).autowire();
		given(DuplicateDoesNotOverrideConfig.SCR.loadContext(any())).willReturn(mock(SecurityContext.class));
		this.mvc.perform(get("/"));
		verify(DuplicateDoesNotOverrideConfig.SCR).loadContext(any(HttpRequestResponseHolder.class));
	}

	// SEC-2932
	@Test
	public void securityContextWhenSecurityContextRepositoryNotConfiguredThenDoesNotThrowException() throws Exception {
		this.spring.register(SecurityContextRepositoryDefaultsSecurityContextRepositoryConfig.class).autowire();
		this.mvc.perform(get("/"));
	}

	@Test
	public void requestWhenSecurityContextWithDefaultsInLambdaThenSessionIsCreated() throws Exception {
		this.spring.register(SecurityContextWithDefaultsInLambdaConfig.class).autowire();
		MvcResult mvcResult = this.mvc.perform(formLogin()).andReturn();
		HttpSession session = mvcResult.getRequest().getSession(false);
		assertThat(session).isNotNull();
	}

	@Test
	public void requestWhenSecurityContextDisabledInLambdaThenContextNotSavedInSession() throws Exception {
		this.spring.register(SecurityContextDisabledInLambdaConfig.class).autowire();
		MvcResult mvcResult = this.mvc.perform(formLogin()).andReturn();
		HttpSession session = mvcResult.getRequest().getSession(false);
		assertThat(session).isNull();
	}

	@Test
	public void requestWhenNullSecurityContextRepositoryInLambdaThenContextNotSavedInSession() throws Exception {
		this.spring.register(NullSecurityContextRepositoryInLambdaConfig.class).autowire();
		MvcResult mvcResult = this.mvc.perform(formLogin()).andReturn();
		HttpSession session = mvcResult.getRequest().getSession(false);
		assertThat(session).isNull();
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

	@Configuration
	@EnableWebSecurity
	static class SecurityContextRepositoryDefaultsSecurityContextRepositoryConfig extends WebSecurityConfigurerAdapter {

		SecurityContextRepositoryDefaultsSecurityContextRepositoryConfig() {
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

	@EnableWebSecurity
	static class SecurityContextWithDefaultsInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.formLogin(withDefaults())
				.securityContext(withDefaults());
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user());
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class SecurityContextDisabledInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.formLogin(withDefaults())
				.securityContext(AbstractHttpConfigurer::disable);
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user());
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class NullSecurityContextRepositoryInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.formLogin(withDefaults())
				.securityContext((securityContext) ->
					securityContext
						.securityContextRepository(new NullSecurityContextRepository())
				);
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user());
			// @formatter:on
		}

	}

}
