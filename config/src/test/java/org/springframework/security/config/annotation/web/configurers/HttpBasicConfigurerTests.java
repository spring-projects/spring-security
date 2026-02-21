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

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationHandler;
import io.micrometer.observation.ObservationRegistry;
import io.micrometer.observation.ObservationTextPublisher;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationObservationContext;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityContextChangedListenerConfig;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.observation.SecurityObservationSettings;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextChangedListener;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.config.annotation.SecurityContextChangedListenerArgumentMatchers.setAuthentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link HttpBasicConfigurer}
 *
 * @author Rob Winch
 * @author Eleftheria Stein
 * @author Evgeniy Cheban
 */
@ExtendWith(SpringTestContextExtension.class)
public class HttpBasicConfigurerTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnBasicAuthenticationFilter() {
		this.spring.register(ObjectPostProcessorConfig.class).autowire();
		verify(ObjectPostProcessorConfig.objectPostProcessor).postProcess(any(BasicAuthenticationFilter.class));
	}

	@Test
	public void httpBasicWhenUsingDefaultsInLambdaThenResponseIncludesBasicChallenge() throws Exception {
		this.spring.register(DefaultsLambdaEntryPointConfig.class).autowire();
		// @formatter:off
		this.mvc.perform(get("/"))
				.andExpect(status().isUnauthorized())
				.andExpect(header().string("WWW-Authenticate", "Basic realm=\"Realm\", charset=\"UTF-8\""));
		// @formatter:on
	}

	// SEC-2198
	@Test
	public void httpBasicWhenUsingDefaultsThenResponseIncludesBasicChallenge() throws Exception {
		this.spring.register(DefaultsEntryPointConfig.class).autowire();
		// @formatter:off
		this.mvc.perform(get("/"))
				.andExpect(status().isUnauthorized())
				.andExpect(header().string("WWW-Authenticate", "Basic realm=\"Realm\", charset=\"UTF-8\""));
		// @formatter:on
	}

	@Test
	public void httpBasicWhenUsingCustomAuthenticationEntryPointThenResponseIncludesBasicChallenge() throws Exception {
		CustomAuthenticationEntryPointConfig.ENTRY_POINT = mock(AuthenticationEntryPoint.class);
		this.spring.register(CustomAuthenticationEntryPointConfig.class).autowire();
		this.mvc.perform(get("/"));
		verify(CustomAuthenticationEntryPointConfig.ENTRY_POINT).commence(any(HttpServletRequest.class),
				any(HttpServletResponse.class), any(AuthenticationException.class));
	}

	@Test
	public void httpBasicWhenInvokedTwiceThenUsesOriginalEntryPoint() throws Exception {
		this.spring.register(DuplicateDoesNotOverrideConfig.class).autowire();
		this.mvc.perform(get("/"));
		verify(DuplicateDoesNotOverrideConfig.ENTRY_POINT).commence(any(HttpServletRequest.class),
				any(HttpServletResponse.class), any(AuthenticationException.class));
	}

	// SEC-3019
	@Test
	public void httpBasicWhenRememberMeConfiguredThenSetsRememberMeCookie() throws Exception {
		this.spring.register(BasicUsesRememberMeConfig.class, Home.class).autowire();
		MockHttpServletRequestBuilder rememberMeRequest = get("/").with(httpBasic("user", "password"))
			.param("remember-me", "true");
		this.mvc.perform(rememberMeRequest).andExpect(cookie().exists("remember-me"));
	}

	@Test
	public void httpBasicWhenDefaultsThenAcceptsBasicCredentials() throws Exception {
		this.spring.register(HttpBasic.class, Users.class, Home.class).autowire();
		this.mvc.perform(get("/").with(httpBasic("user", "password")))
			.andExpect(status().isOk())
			.andExpect(content().string("user"));
	}

	@Test
	public void httpBasicWhenCustomSecurityContextHolderStrategyThenUses() throws Exception {
		this.spring.register(HttpBasic.class, Users.class, Home.class, SecurityContextChangedListenerConfig.class)
			.autowire();
		this.mvc.perform(get("/").with(httpBasic("user", "password")))
			.andExpect(status().isOk())
			.andExpect(content().string("user"));
		SecurityContextChangedListener listener = this.spring.getContext()
			.getBean(SecurityContextChangedListener.class);
		verify(listener).securityContextChanged(setAuthentication(UsernamePasswordAuthenticationToken.class));
	}

	@Test
	public void httpBasicWhenUsingCustomSecurityContextRepositoryThenUses() throws Exception {
		this.spring.register(CustomSecurityContextRepositoryConfig.class, Users.class, Home.class).autowire();
		this.mvc.perform(get("/").with(httpBasic("user", "password")))
			.andExpect(status().isOk())
			.andExpect(content().string("user"));
		verify(CustomSecurityContextRepositoryConfig.SECURITY_CONTEXT_REPOSITORY)
			.saveContext(any(SecurityContext.class), any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void httpBasicWhenObservationRegistryThenObserves() throws Exception {
		this.spring.register(HttpBasic.class, Users.class, Home.class, ObservationRegistryConfig.class).autowire();
		ObservationHandler<Observation.Context> handler = this.spring.getContext().getBean(ObservationHandler.class);
		this.mvc.perform(get("/").with(httpBasic("user", "password")))
			.andExpect(status().isOk())
			.andExpect(content().string("user"));
		ArgumentCaptor<Observation.Context> context = ArgumentCaptor.forClass(Observation.Context.class);
		verify(handler, atLeastOnce()).onStart(context.capture());
		assertThat(context.getAllValues()).anyMatch((c) -> c instanceof AuthenticationObservationContext);
		verify(handler, atLeastOnce()).onStop(context.capture());
		assertThat(context.getAllValues()).anyMatch((c) -> c instanceof AuthenticationObservationContext);
		this.mvc.perform(get("/").with(httpBasic("user", "wrong"))).andExpect(status().isUnauthorized());
		verify(handler).onError(context.capture());
		assertThat(context.getValue()).isInstanceOf(AuthenticationObservationContext.class);
	}

	@Test
	public void httpBasicWhenExcludeAuthenticationObservationsThenUnobserved() throws Exception {
		this.spring
			.register(HttpBasic.class, Users.class, Home.class, ObservationRegistryConfig.class,
					SelectableObservationsConfig.class)
			.autowire();
		ObservationHandler<Observation.Context> handler = this.spring.getContext().getBean(ObservationHandler.class);
		this.mvc.perform(get("/").with(httpBasic("user", "password")))
			.andExpect(status().isOk())
			.andExpect(content().string("user"));
		ArgumentCaptor<Observation.Context> context = ArgumentCaptor.forClass(Observation.Context.class);
		verify(handler, atLeastOnce()).onStart(context.capture());
		assertThat(context.getAllValues()).noneMatch((c) -> c instanceof AuthenticationObservationContext);
		context = ArgumentCaptor.forClass(Observation.Context.class);
		verify(handler, atLeastOnce()).onStop(context.capture());
		assertThat(context.getAllValues()).noneMatch((c) -> c instanceof AuthenticationObservationContext);
		this.mvc.perform(get("/").with(httpBasic("user", "wrong"))).andExpect(status().isUnauthorized());
		verify(handler, never()).onError(any());
	}

	@Configuration
	@EnableWebSecurity
	static class ObjectPostProcessorConfig {

		static ObjectPostProcessor<Object> objectPostProcessor = spy(ReflectingObjectPostProcessor.class);

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic(withDefaults());
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
	static class DefaultsLambdaEntryPointConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((authorize) -> authorize
						.anyRequest().authenticated()
				)
				.httpBasic(withDefaults());
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class DefaultsEntryPointConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((requests) -> requests
					.anyRequest().authenticated())
				.httpBasic(withDefaults());
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CustomAuthenticationEntryPointConfig {

		static AuthenticationEntryPoint ENTRY_POINT;

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((requests) -> requests
					.anyRequest().authenticated())
				.httpBasic((basic) -> basic
					.authenticationEntryPoint(ENTRY_POINT));
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class DuplicateDoesNotOverrideConfig {

		static AuthenticationEntryPoint ENTRY_POINT = mock(AuthenticationEntryPoint.class);

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((requests) -> requests
					.anyRequest().authenticated())
				.httpBasic((basic) -> basic
					.authenticationEntryPoint(ENTRY_POINT))
				.httpBasic(withDefaults());
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager();
		}

	}

	@EnableWebSecurity
	@Configuration
	static class BasicUsesRememberMeConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic(withDefaults())
				.rememberMe(withDefaults());
			return http.build();
			// @formatter:on
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(
			// @formatter:off
					org.springframework.security.core.userdetails.User.withDefaultPasswordEncoder()
							.username("user")
							.password("password")
							.roles("USER")
							.build()
					// @formatter:on
			);
		}

	}

	@Configuration
	@EnableWebSecurity
	static class HttpBasic {

		@Bean
		SecurityFilterChain web(HttpSecurity http) throws Exception {
			http.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
				.httpBasic(Customizer.withDefaults());

			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CustomSecurityContextRepositoryConfig {

		static final SecurityContextRepository SECURITY_CONTEXT_REPOSITORY = mock(SecurityContextRepository.class);

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic((basic) -> basic
					.securityContextRepository(SECURITY_CONTEXT_REPOSITORY));
			// @formatter:on
			return http.build();
		}

	}

	@Configuration
	static class Users {

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(
			// @formatter:off
					User.withDefaultPasswordEncoder()
							.username("user")
							.password("password")
							.roles("USER")
							.build()
					// @formatter:on
			);
		}

	}

	@EnableWebMvc
	@RestController
	static class Home {

		@GetMapping("/")
		String home(@AuthenticationPrincipal UserDetails user) {
			return user.getUsername();
		}

	}

	@Configuration
	static class ObservationRegistryConfig {

		private final ObservationRegistry registry = ObservationRegistry.create();

		private final ObservationHandler<Observation.Context> handler = spy(new ObservationTextPublisher());

		@Bean
		ObservationRegistry observationRegistry() {
			return this.registry;
		}

		@Bean
		ObservationHandler<Observation.Context> observationHandler() {
			return this.handler;
		}

		@Bean
		ObservationRegistryPostProcessor observationRegistryPostProcessor(
				ObjectProvider<ObservationHandler<Observation.Context>> handler) {
			return new ObservationRegistryPostProcessor(handler);
		}

	}

	static class ObservationRegistryPostProcessor implements BeanPostProcessor {

		private final ObjectProvider<ObservationHandler<Observation.Context>> handler;

		ObservationRegistryPostProcessor(ObjectProvider<ObservationHandler<Observation.Context>> handler) {
			this.handler = handler;
		}

		@Override
		public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
			if (bean instanceof ObservationRegistry registry) {
				registry.observationConfig().observationHandler(this.handler.getObject());
			}
			return bean;
		}

	}

	@Configuration
	static class SelectableObservationsConfig {

		@Bean
		SecurityObservationSettings observabilityDefaults() {
			return SecurityObservationSettings.withDefaults().shouldObserveAuthentications(false).build();
		}

	}

}
