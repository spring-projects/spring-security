/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.config.annotation.web.configuration;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;

import com.google.common.net.HttpHeaders;
import io.micrometer.observation.ObservationRegistry;
import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.EventListener;
import org.springframework.core.io.support.SpringFactoriesLoader;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.TestingAuthenticationProvider;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.authentication.password.CompromisedPasswordDecision;
import org.springframework.security.authentication.password.CompromisedPasswordException;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.SecurityContextChangedListenerConfig;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.AnonymousConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.test.web.servlet.RequestCacheResultMatcher;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.authentication.ui.DefaultLogoutPageGeneratingFilter;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link HttpSecurityConfiguration}.
 *
 * @author Eleftheria Stein
 */
@ExtendWith({ MockitoExtension.class, SpringTestContextExtension.class })
public class HttpSecurityConfigurationTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	private MockMvc mockMvc;

	@Mock
	private MockedStatic<SpringFactoriesLoader> springFactoriesLoader;

	@Test
	public void postWhenDefaultFilterChainBeanThenRespondsWithForbidden() throws Exception {
		this.spring.register(DefaultWithFilterChainConfig.class).autowire();

		this.mockMvc.perform(post("/")).andExpect(status().isForbidden());
	}

	@Test
	public void getWhenDefaultFilterChainBeanThenDefaultHeadersInResponse() throws Exception {
		this.spring.register(DefaultWithFilterChainConfig.class).autowire();
		// @formatter:off
		MvcResult mvcResult = this.mockMvc.perform(get("/").secure(true))
				.andExpect(header().string(HttpHeaders.X_CONTENT_TYPE_OPTIONS, "nosniff"))
				.andExpect(header().string(HttpHeaders.X_FRAME_OPTIONS,
						XFrameOptionsHeaderWriter.XFrameOptionsMode.DENY.name()))
				.andExpect(
						header().string(HttpHeaders.STRICT_TRANSPORT_SECURITY, "max-age=31536000 ; includeSubDomains"))
				.andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-cache, no-store, max-age=0, must-revalidate"))
				.andExpect(header().string(HttpHeaders.EXPIRES, "0"))
				.andExpect(header().string(HttpHeaders.PRAGMA, "no-cache"))
				.andExpect(header().string(HttpHeaders.X_XSS_PROTECTION, "0"))
				.andReturn();
		// @formatter:on
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactlyInAnyOrder(
				HttpHeaders.X_CONTENT_TYPE_OPTIONS, HttpHeaders.X_FRAME_OPTIONS, HttpHeaders.STRICT_TRANSPORT_SECURITY,
				HttpHeaders.CACHE_CONTROL, HttpHeaders.EXPIRES, HttpHeaders.PRAGMA, HttpHeaders.X_XSS_PROTECTION);
	}

	@Test
	public void logoutWhenDefaultFilterChainBeanThenCreatesDefaultLogoutEndpoint() throws Exception {
		this.spring.register(DefaultWithFilterChainConfig.class).autowire();
		// @formatter:off
		this.mockMvc.perform(post("/logout").with(csrf()))
				.andExpect(redirectedUrl("/login?logout"));
		// @formatter:on
	}

	@Test
	public void loadConfigWhenDefaultConfigThenWebAsyncManagerIntegrationFilterAdded() throws Exception {
		this.spring.register(DefaultWithFilterChainConfig.class, NameController.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder requestWithBob = get("/name").with(user("Bob"));
		MvcResult mvcResult = this.mockMvc.perform(requestWithBob)
				.andExpect(request().asyncStarted())
				.andReturn();
		this.mockMvc.perform(asyncDispatch(mvcResult))
				.andExpect(status().isOk())
				.andExpect(content().string("Bob"));
		// @formatter:on
	}

	@Test
	public void asyncDispatchWhenCustomSecurityContextHolderStrategyThenUses() throws Exception {
		this.spring
			.register(DefaultWithFilterChainConfig.class, SecurityContextChangedListenerConfig.class,
					NameController.class)
			.autowire();
		// @formatter:off
		MockHttpServletRequestBuilder requestWithBob = get("/name").with(user("Bob"));
		MvcResult mvcResult = this.mockMvc.perform(requestWithBob)
				.andExpect(request().asyncStarted())
				.andReturn();
		this.mockMvc.perform(asyncDispatch(mvcResult))
				.andExpect(status().isOk())
				.andExpect(content().string("Bob"));
		// @formatter:on
		verify(this.spring.getContext().getBean(SecurityContextHolderStrategy.class), atLeastOnce()).getContext();
	}

	@Test
	public void getWhenDefaultFilterChainBeanThenAnonymousPermitted() throws Exception {
		this.spring.register(AuthorizeRequestsConfig.class, UserDetailsConfig.class, BaseController.class).autowire();
		// @formatter:off
		this.mockMvc.perform(get("/"))
				.andExpect(status().isOk());
		// @formatter:on
	}

	@Test
	public void authenticateWhenDefaultFilterChainBeanThenSessionIdChanges() throws Exception {
		this.spring.register(SecurityEnabledConfig.class, UserDetailsConfig.class).autowire();
		MockHttpSession session = new MockHttpSession();
		String sessionId = session.getId();
		// @formatter:off
		MockHttpServletRequestBuilder loginRequest = post("/login")
				.param("username", "user")
				.param("password", "password")
				.session(session)
				.with(csrf());
		// @formatter:on
		MvcResult result = this.mockMvc.perform(loginRequest).andReturn();
		assertThat(result.getRequest().getSession(false).getId()).isNotEqualTo(sessionId);
	}

	@Test
	public void authenticateWhenDefaultFilterChainBeanThenRedirectsToSavedRequest() throws Exception {
		this.spring.register(SecurityEnabledConfig.class, UserDetailsConfig.class).autowire();
		// @formatter:off
		MvcResult mvcResult = this.mockMvc.perform(get("/messages"))
				.andReturn();
		HttpServletRequest request = mvcResult.getRequest();
		HttpServletResponse response = mvcResult.getResponse();
		MockHttpSession session = (MockHttpSession) mvcResult
				.getRequest()
				.getSession();
		// @formatter:on
		// @formatter:off
		MockHttpServletRequestBuilder loginRequest = post("/login")
				.param("username", "user")
				.param("password", "password")
				.session(session)
				.with(csrf());
		this.mockMvc.perform(loginRequest)
				.andExpect(RequestCacheResultMatcher.redirectToCachedRequest());
		// @formatter:on
	}

	@Test
	public void authenticateWhenDefaultFilterChainBeanThenRolePrefixIsSet() throws Exception {
		this.spring.register(SecurityEnabledConfig.class, UserDetailsConfig.class, UserController.class).autowire();
		TestingAuthenticationToken user = new TestingAuthenticationToken("user", "password", "ROLE_USER");
		// @formatter:off
		this.mockMvc
				.perform(get("/user").with(authentication(user)))
				.andExpect(status().isOk());
		// @formatter:on
	}

	@Test
	public void loginWhenUsingDefaultsThenDefaultLoginPageGenerated() throws Exception {
		this.spring.register(SecurityEnabledConfig.class).autowire();
		this.mockMvc.perform(get("/login")).andExpect(status().isOk());
	}

	@Test
	public void loginWhenUsingDefaultsThenDefaultLoginFailurePageGenerated() throws Exception {
		this.spring.register(SecurityEnabledConfig.class).autowire();
		this.mockMvc.perform(get("/login?error")).andExpect(status().isOk());
	}

	@Test
	public void loginWhenUsingDefaultsThenDefaultLogoutSuccessPageGenerated() throws Exception {
		this.spring.register(SecurityEnabledConfig.class).autowire();
		this.mockMvc.perform(get("/login?logout")).andExpect(status().isOk());
	}

	@Test
	public void loginWhenUsingDefaultThenAuthenticationEventPublished() throws Exception {
		this.spring
			.register(SecurityEnabledConfig.class, UserDetailsConfig.class, AuthenticationEventListenerConfig.class)
			.autowire();
		AuthenticationEventListenerConfig.clearEvents();
		this.mockMvc.perform(formLogin()).andExpect(status().is3xxRedirection());
		assertThat(AuthenticationEventListenerConfig.EVENTS).isNotEmpty();
		assertThat(AuthenticationEventListenerConfig.EVENTS).hasSize(1);
	}

	@Test
	public void loginWhenUsingDefaultAndNoUserDetailsServiceThenAuthenticationEventPublished() throws Exception {
		this.spring
			.register(SecurityEnabledConfig.class, UserDetailsConfig.class, AuthenticationEventListenerConfig.class)
			.autowire();
		AuthenticationEventListenerConfig.clearEvents();
		this.mockMvc.perform(formLogin()).andExpect(status().is3xxRedirection());
		assertThat(AuthenticationEventListenerConfig.EVENTS).isNotEmpty();
		assertThat(AuthenticationEventListenerConfig.EVENTS).hasSize(1);
	}

	@Test
	public void loginWhenUsingCustomAuthenticationEventPublisherThenAuthenticationEventPublished() throws Exception {
		this.spring
			.register(SecurityEnabledConfig.class, UserDetailsConfig.class,
					CustomAuthenticationEventPublisherConfig.class)
			.autowire();
		CustomAuthenticationEventPublisherConfig.clearEvents();
		this.mockMvc.perform(formLogin()).andExpect(status().is3xxRedirection());
		assertThat(CustomAuthenticationEventPublisherConfig.EVENTS).isNotEmpty();
		assertThat(CustomAuthenticationEventPublisherConfig.EVENTS).hasSize(1);
	}

	@Test
	public void loginWhenUsingCustomAuthenticationEventPublisherAndNoUserDetailsServiceThenAuthenticationEventPublished()
			throws Exception {
		this.spring.register(SecurityEnabledConfig.class, CustomAuthenticationEventPublisherConfig.class).autowire();
		CustomAuthenticationEventPublisherConfig.clearEvents();
		this.mockMvc.perform(formLogin()).andExpect(status().is3xxRedirection());
		assertThat(CustomAuthenticationEventPublisherConfig.EVENTS).isNotEmpty();
		assertThat(CustomAuthenticationEventPublisherConfig.EVENTS).hasSize(1);
	}

	@Test
	public void configureWhenAuthorizeHttpRequestsBeforeAuthorizeRequestThenException() {
		assertThatExceptionOfType(BeanCreationException.class)
			.isThrownBy(() -> this.spring.register(AuthorizeHttpRequestsBeforeAuthorizeRequestsConfig.class).autowire())
			.withMessageContaining(
					"authorizeHttpRequests cannot be used in conjunction with authorizeRequests. Please select just one.");
	}

	@Test
	public void configureWhenAuthorizeHttpRequestsAfterAuthorizeRequestThenException() {
		assertThatExceptionOfType(BeanCreationException.class)
			.isThrownBy(() -> this.spring.register(AuthorizeHttpRequestsAfterAuthorizeRequestsConfig.class).autowire())
			.withMessageContaining(
					"authorizeHttpRequests cannot be used in conjunction with authorizeRequests. Please select just one.");
	}

	@Test
	public void configureWhenDefaultConfigurerAsSpringFactoryThenDefaultConfigurerApplied() {
		DefaultConfigurer configurer = new DefaultConfigurer();
		this.springFactoriesLoader
			.when(() -> SpringFactoriesLoader.loadFactories(AbstractHttpConfigurer.class, getClass().getClassLoader()))
			.thenReturn(Arrays.asList(configurer));
		this.spring.register(DefaultWithFilterChainConfig.class).autowire();
		assertThat(configurer.init).isTrue();
		assertThat(configurer.configure).isTrue();
	}

	@Test
	public void getWhenCustomContentNegotiationStrategyThenUses() throws Exception {
		this.spring.register(CustomContentNegotiationStrategyConfig.class).autowire();
		this.mockMvc.perform(get("/"));
		verify(CustomContentNegotiationStrategyConfig.CNS, atLeastOnce())
			.resolveMediaTypes(any(NativeWebRequest.class));
	}

	// gh-13084
	@Test
	public void configureWhenNoAuthenticationManagerAndObservationRegistryNotNoOpThenConfigure() throws Exception {
		this.spring.register(ObservationConfig.class, NoAuthenticationManagerConfig.class).autowire();
		this.mockMvc.perform(get("/"));
	}

	// gh-13203
	@Test
	public void disableConfigurerWhenAppliedByAnotherConfigurerThenNotApplied() {
		this.spring.register(ApplyCustomDslConfig.class).autowire();
		SecurityFilterChain filterChain = this.spring.getContext().getBean(SecurityFilterChain.class);
		List<Filter> filters = filterChain.getFilters();
		assertThat(filters).doesNotHaveAnyElementsOfTypes(DefaultLoginPageGeneratingFilter.class,
				DefaultLogoutPageGeneratingFilter.class);
	}

	@Test
	public void configureWhenCorsConfigurationSourceThenApplyCors() throws Exception {
		this.spring.register(CorsConfigurationSourceConfig.class, DefaultWithFilterChainConfig.class).autowire();
		SecurityFilterChain filterChain = this.spring.getContext().getBean(SecurityFilterChain.class);
		CorsFilter corsFilter = (CorsFilter) filterChain.getFilters()
			.stream()
			.filter((f) -> f instanceof CorsFilter)
			.findFirst()
			.get();
		Object configSource = ReflectionTestUtils.getField(corsFilter, "configSource");
		assertThat(configSource).isInstanceOf(UrlBasedCorsConfigurationSource.class);
	}

	// gh-15378
	@Test
	public void configureWhenNoUrlBasedCorsConfigThenNoCorsAppliedAndVaryHeaderNotPresent() throws Exception {
		this.spring.register(NonUrlBasedCorsConfig.class, DefaultWithFilterChainConfig.class).autowire();
		SecurityFilterChain filterChain = this.spring.getContext().getBean(SecurityFilterChain.class);
		assertThat(filterChain.getFilters()).noneMatch((filter) -> filter instanceof CorsFilter);

		this.mockMvc.perform(get("/")).andExpect(header().doesNotExist("Vary"));
	}

	@Test
	public void configureWhenAddingCustomDslUsingWithThenApplied() throws Exception {
		this.spring.register(WithCustomDslConfig.class, UserDetailsConfig.class).autowire();
		SecurityFilterChain filterChain = this.spring.getContext().getBean(SecurityFilterChain.class);
		List<Filter> filters = filterChain.getFilters();
		assertThat(filters).hasAtLeastOneElementOfType(UsernamePasswordAuthenticationFilter.class);
		this.mockMvc.perform(formLogin()).andExpectAll(redirectedUrl("/"), authenticated());
	}

	@Test
	public void configureWhenCustomDslAddedFromFactoriesAndDisablingUsingWithThenNotApplied() throws Exception {
		this.springFactoriesLoader
			.when(() -> SpringFactoriesLoader.loadFactories(AbstractHttpConfigurer.class, getClass().getClassLoader()))
			.thenReturn(List.of(new WithCustomDsl()));
		this.spring.register(WithCustomDslDisabledConfig.class, UserDetailsConfig.class).autowire();
		SecurityFilterChain filterChain = this.spring.getContext().getBean(SecurityFilterChain.class);
		List<Filter> filters = filterChain.getFilters();
		assertThat(filters).doesNotHaveAnyElementsOfTypes(UsernamePasswordAuthenticationFilter.class);
		this.mockMvc.perform(formLogin()).andExpectAll(status().isNotFound(), unauthenticated());
	}

	@Test
	void loginWhenCompromisePasswordCheckerConfiguredAndPasswordCompromisedThenUnauthorized() throws Exception {
		this.spring
			.register(SecurityEnabledConfig.class, UserDetailsConfig.class, CompromisedPasswordCheckerConfig.class)
			.autowire();
		this.mockMvc.perform(formLogin().password("password"))
			.andExpectAll(status().isFound(), redirectedUrl("/login?error"), unauthenticated());
	}

	@Test
	void loginWhenCompromisedPasswordAndRedirectIfPasswordExceptionThenRedirectedToResetPassword() throws Exception {
		this.spring
			.register(SecurityEnabledRedirectIfPasswordExceptionConfig.class, UserDetailsConfig.class,
					CompromisedPasswordCheckerConfig.class)
			.autowire();
		this.mockMvc.perform(formLogin().password("password"))
			.andExpectAll(status().isFound(), redirectedUrl("/reset-password"), unauthenticated());
	}

	@Test
	void loginWhenCompromisePasswordCheckerConfiguredAndPasswordNotCompromisedThenSuccess() throws Exception {
		this.spring
			.register(SecurityEnabledConfig.class, UserDetailsConfig.class, CompromisedPasswordCheckerConfig.class)
			.autowire();
		UserDetailsManager userDetailsManager = this.spring.getContext().getBean(UserDetailsManager.class);
		UserDetails notCompromisedPwUser = User.withDefaultPasswordEncoder()
			.username("user2")
			.password("password2")
			.roles("USER")
			.build();
		userDetailsManager.createUser(notCompromisedPwUser);
		this.mockMvc.perform(formLogin().user("user2").password("password2"))
			.andExpectAll(status().isFound(), redirectedUrl("/"), authenticated());
	}

	@RestController
	static class NameController {

		@GetMapping("/name")
		Callable<String> name(Authentication authentication) {
			return () -> authentication.getName();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class DefaultWithFilterChainConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class AuthorizeRequestsConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			return http
					.authorizeRequests((authorize) -> authorize
						.anyRequest().permitAll()
					)
					.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class SecurityEnabledConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			return http
					.authorizeRequests((authorize) -> authorize
						.anyRequest().authenticated()
					)
					.formLogin(withDefaults())
					.build();
			// @formatter:on
		}

	}

	@Configuration
	static class UserDetailsConfig {

		@Bean
		InMemoryUserDetailsManager userDetailsService() {
			// @formatter:off
			UserDetails user = User.withDefaultPasswordEncoder()
					.username("user")
					.password("password")
					.roles("USER")
					.build();
			// @formatter:on
			return new InMemoryUserDetailsManager(user);
		}

	}

	@Configuration
	@EnableWebSecurity
	static class AuthorizeHttpRequestsBeforeAuthorizeRequestsConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			return http
					.authorizeHttpRequests((requests) -> requests
							.anyRequest().authenticated()
					)
					.authorizeRequests((requests) -> requests
							.anyRequest().authenticated()
					)
					.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class AuthorizeHttpRequestsAfterAuthorizeRequestsConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			return http
					.authorizeRequests((requests) -> requests
							.anyRequest().authenticated()
					)
					.authorizeHttpRequests((requests) -> requests
							.anyRequest().authenticated()
					)
					.build();
			// @formatter:on
		}

	}

	@Configuration
	static class CustomAuthenticationEventPublisherConfig {

		static List<Authentication> EVENTS = new ArrayList<>();

		static void clearEvents() {
			EVENTS.clear();
		}

		@Bean
		AuthenticationEventPublisher publisher() {
			return new AuthenticationEventPublisher() {

				@Override
				public void publishAuthenticationSuccess(Authentication authentication) {
					EVENTS.add(authentication);
				}

				@Override
				public void publishAuthenticationFailure(AuthenticationException exception,
						Authentication authentication) {
					EVENTS.add(authentication);
				}
			};
		}

	}

	@Configuration
	static class AuthenticationEventListenerConfig {

		static List<AbstractAuthenticationEvent> EVENTS = new ArrayList<>();

		static void clearEvents() {
			EVENTS.clear();
		}

		@EventListener
		void onAuthenticationSuccessEvent(AuthenticationSuccessEvent event) {
			EVENTS.add(event);
		}

		@EventListener
		void onAuthenticationFailureEvent(AbstractAuthenticationFailureEvent event) {
			EVENTS.add(event);
		}

	}

	@RestController
	static class BaseController {

		@GetMapping("/")
		void index() {
		}

	}

	@RestController
	static class UserController {

		@GetMapping("/user")
		void user(HttpServletRequest request) {
			if (!request.isUserInRole("USER")) {
				throw new AccessDeniedException("This resource is only available to users");
			}
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CustomContentNegotiationStrategyConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.authorizeHttpRequests((requests) -> requests
							.anyRequest().authenticated()
					);
			// @formatter:on
			return http.build();
		}

		static ContentNegotiationStrategy CNS = mock(ContentNegotiationStrategy.class);

		@Bean
		static ContentNegotiationStrategy cns() {
			return CNS;
		}

	}

	@Configuration
	@EnableWebSecurity
	static class NoAuthenticationManagerConfig {

		@Bean
		SecurityFilterChain apiSecurity(HttpSecurity http) throws Exception {
			http.anonymous(AnonymousConfigurer::disable);
			return http.build();
		}

		@Bean
		AuthenticationProvider authenticationProvider1() {
			return new TestingAuthenticationProvider();
		}

		@Bean
		AuthenticationProvider authenticationProvider2() {
			return new TestingAuthenticationProvider();
		}

	}

	@Configuration
	static class ObservationConfig {

		@Bean
		ObservationRegistry observationRegistry() {
			return ObservationRegistry.create();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class ApplyCustomDslConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			http.apply(CustomDsl.customDsl());
			return http.build();
		}

	}

	static class CustomDsl extends AbstractHttpConfigurer<CustomDsl, HttpSecurity> {

		@Override
		public void init(HttpSecurity http) throws Exception {
			http.formLogin(FormLoginConfigurer::disable);
		}

		static CustomDsl customDsl() {
			return new CustomDsl();
		}

	}

	@Configuration
	static class CorsConfigurationSourceConfig {

		@Bean
		CorsConfigurationSource corsConfigurationSource() {
			UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
			CorsConfiguration corsConfiguration = new CorsConfiguration();
			corsConfiguration.setAllowedOrigins(List.of("http://localhost:8080"));
			source.registerCorsConfiguration("/**", corsConfiguration);
			return source;
		}

	}

	@Configuration
	@EnableWebSecurity
	static class NonUrlBasedCorsConfig {

		@Bean
		CorsConfigurationSource corsConfigurationSource() {
			return new CustomCorsConfigurationSource();
		}

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			return http.build();
		}

	}

	static class CustomCorsConfigurationSource implements CorsConfigurationSource {

		@Override
		public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
			CorsConfiguration configuration = new CorsConfiguration();
			configuration.setAllowedOrigins(List.of("http://localhost:8080"));
			return configuration;
		}

	}

	static class DefaultConfigurer extends AbstractHttpConfigurer<DefaultConfigurer, HttpSecurity> {

		boolean init;

		boolean configure;

		@Override
		public void init(HttpSecurity builder) {
			this.init = true;
		}

		@Override
		public void configure(HttpSecurity builder) {
			this.configure = true;
		}

	}

	@Configuration
	@EnableWebSecurity
	static class WithCustomDslConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.with(new WithCustomDsl(), Customizer.withDefaults())
					.httpBasic(Customizer.withDefaults());
			// @formatter:on
			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class WithCustomDslDisabledConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.with(new WithCustomDsl(), (dsl) -> dsl.disable())
					.httpBasic(Customizer.withDefaults());
			// @formatter:on
			return http.build();
		}

	}

	static class WithCustomDsl extends AbstractHttpConfigurer<WithCustomDsl, HttpSecurity> {

		@Override
		public void init(HttpSecurity builder) throws Exception {
			builder.formLogin(Customizer.withDefaults());
		}

	}

	@Configuration(proxyBeanMethods = false)
	static class CompromisedPasswordCheckerConfig {

		@Bean
		TestCompromisedPasswordChecker compromisedPasswordChecker() {
			return new TestCompromisedPasswordChecker();
		}

	}

	@Configuration(proxyBeanMethods = false)
	@EnableWebSecurity
	static class SecurityEnabledRedirectIfPasswordExceptionConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			return http
					.authorizeHttpRequests((authorize) -> authorize
							.anyRequest().authenticated()
					)
					.formLogin((form) -> form
							.failureHandler((request, response, exception) -> {
								if (exception instanceof CompromisedPasswordException) {
									response.sendRedirect("/reset-password");
									return;
								}
								response.sendRedirect("/login?error");
							})
					)
					.build();
			// @formatter:on
		}

	}

	private static class TestCompromisedPasswordChecker implements CompromisedPasswordChecker {

		@Override
		public CompromisedPasswordDecision check(String password) {
			if ("password".equals(password)) {
				return new CompromisedPasswordDecision(true);
			}
			return new CompromisedPasswordDecision(false);
		}

	}

}
