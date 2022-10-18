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

import java.util.List;
import java.util.stream.Collectors;

import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.TestDeferredSecurityContext;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.TestHttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextHolderFilter;
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
@ExtendWith(SpringTestContextExtension.class)
public class SecurityContextConfigurerTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnSecurityContextPersistenceFilter() {
		this.spring.register(ObjectPostProcessorConfig.class).autowire();
		verify(ObjectPostProcessorConfig.objectPostProcessor).postProcess(any(SecurityContextHolderFilter.class));
	}

	@Test
	public void securityContextWhenInvokedTwiceThenUsesOriginalSecurityContextRepository() throws Exception {
		this.spring.register(DuplicateDoesNotOverrideConfig.class).autowire();
		given(DuplicateDoesNotOverrideConfig.SCR.loadDeferredContext(any(HttpServletRequest.class)))
				.willReturn(new TestDeferredSecurityContext(mock(SecurityContext.class), false));
		this.mvc.perform(get("/"));
		verify(DuplicateDoesNotOverrideConfig.SCR).loadDeferredContext(any(HttpServletRequest.class));
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

	@Test
	public void requireExplicitSave() throws Exception {
		HttpSessionSecurityContextRepository repository = new HttpSessionSecurityContextRepository();
		SpringTestContext testContext = this.spring.register(RequireExplicitSaveConfig.class);
		testContext.autowire();
		FilterChainProxy filterChainProxy = testContext.getContext().getBean(FilterChainProxy.class);
		// @formatter:off
		List<Class<? extends Filter>> filterTypes = filterChainProxy.getFilters("/")
				.stream()
				.map(Filter::getClass)
				.collect(Collectors.toList());
		assertThat(filterTypes)
				.contains(SecurityContextHolderFilter.class)
				.doesNotContain(SecurityContextPersistenceFilter.class);
		// @formatter:on
		MvcResult mvcResult = this.mvc.perform(formLogin()).andReturn();
		SecurityContext securityContext = repository
				.loadContext(new HttpRequestResponseHolder(mvcResult.getRequest(), mvcResult.getResponse()));
		assertThat(securityContext.getAuthentication()).isNotNull();
	}

	@Configuration(proxyBeanMethods = false)
	@EnableWebSecurity
	static class ObjectPostProcessorConfig {

		static ObjectPostProcessor<Object> objectPostProcessor = spy(ReflectingObjectPostProcessor.class);

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.securityContext();
			return http.build();
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

	@Configuration
	@EnableWebSecurity
	static class DuplicateDoesNotOverrideConfig {

		static SecurityContextRepository SCR = mock(SecurityContextRepository.class);

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.securityContext()
					.securityContextRepository(SCR)
					.and()
				.securityContext();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class SecurityContextRepositoryDefaultsSecurityContextRepositoryConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			TestHttpSecurity.disableDefaults(http);
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
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(PasswordEncodedUser.user());
		}

	}

	@Configuration
	@EnableWebSecurity
	static class SecurityContextWithDefaultsInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.formLogin(withDefaults())
				.securityContext(withDefaults());
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(PasswordEncodedUser.user());
		}

	}

	@Configuration
	@EnableWebSecurity
	static class SecurityContextDisabledInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.formLogin(withDefaults())
				.securityContext(AbstractHttpConfigurer::disable);
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(PasswordEncodedUser.user());
		}

	}

	@Configuration
	@EnableWebSecurity
	static class NullSecurityContextRepositoryInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.formLogin(withDefaults())
					.securityContext((securityContext) ->
							securityContext
									.securityContextRepository(new NullSecurityContextRepository())
					);
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(PasswordEncodedUser.user());
		}

	}

	@Configuration
	@EnableWebSecurity
	static class RequireExplicitSaveConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.formLogin(withDefaults())
				.securityContext((securityContext) -> securityContext
					.requireExplicitSave(true)
				);
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(PasswordEncodedUser.user());
		}

	}

}
