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

import java.util.Collections;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.UnsatisfiedDependencyException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityContextChangedListenerConfig;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;

/**
 * Tests for {@link RememberMeConfigurer}
 *
 * @author Rob Winch
 * @author Eddú Meléndez
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension.class)
public class RememberMeConfigurerTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	@Test
	public void postWhenNoUserDetailsServiceThenException() {
		assertThatExceptionOfType(UnsatisfiedDependencyException.class)
				.isThrownBy(() -> this.spring.register(NullUserDetailsConfig.class).autowire())
				.withMessageContaining("userDetailsService cannot be null");
	}

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnRememberMeAuthenticationFilter() {
		this.spring.register(ObjectPostProcessorConfig.class).autowire();
		verify(this.spring.getContext().getBean(ObjectPostProcessor.class))
				.postProcess(any(RememberMeAuthenticationFilter.class));
	}

	@Test
	public void rememberMeWhenInvokedTwiceThenUsesOriginalUserDetailsService() throws Exception {
		given(DuplicateDoesNotOverrideConfig.userDetailsService.loadUserByUsername(anyString()))
				.willReturn(new User("user", "password", Collections.emptyList()));
		this.spring.register(DuplicateDoesNotOverrideConfig.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder request = get("/")
				.with(httpBasic("user", "password"))
				.param("remember-me", "true");
		// @formatter:on
		this.mvc.perform(request);
		verify(DuplicateDoesNotOverrideConfig.userDetailsService).loadUserByUsername("user");
	}

	@Test
	public void rememberMeWhenUserDetailsServiceNotConfiguredThenUsesBean() throws Exception {
		this.spring.register(UserDetailsServiceBeanConfig.class).autowire();
		MvcResult mvcResult = this.mvc.perform(post("/login").with(csrf()).param("username", "user")
				.param("password", "password").param("remember-me", "true")).andReturn();
		Cookie rememberMeCookie = mvcResult.getResponse().getCookie("remember-me");
		// @formatter:off
		MockHttpServletRequestBuilder request = get("/abc").cookie(rememberMeCookie);
		SecurityMockMvcResultMatchers.AuthenticatedMatcher remembermeAuthentication = authenticated()
				.withAuthentication((auth) -> assertThat(auth).isInstanceOf(RememberMeAuthenticationToken.class));
		// @formatter:on
		this.mvc.perform(request).andExpect(remembermeAuthentication);
	}

	@Test
	public void rememberMeWhenCustomSecurityContextHolderStrategyThenUses() throws Exception {
		this.spring.register(UserDetailsServiceBeanConfig.class, SecurityContextChangedListenerConfig.class).autowire();
		MvcResult mvcResult = this.mvc.perform(post("/login").with(csrf()).param("username", "user")
				.param("password", "password").param("remember-me", "true")).andReturn();
		Cookie rememberMeCookie = mvcResult.getResponse().getCookie("remember-me");
		// @formatter:off
		MockHttpServletRequestBuilder request = get("/abc").cookie(rememberMeCookie);
		SecurityMockMvcResultMatchers.AuthenticatedMatcher remembermeAuthentication = authenticated()
				.withAuthentication((auth) -> assertThat(auth).isInstanceOf(RememberMeAuthenticationToken.class));
		// @formatter:on
		this.mvc.perform(request).andExpect(remembermeAuthentication);
		verify(this.spring.getContext().getBean(SecurityContextHolderStrategy.class), atLeastOnce()).getContext();
	}

	@Test
	public void loginWhenRememberMeTrueThenRespondsWithRememberMeCookie() throws Exception {
		this.spring.register(RememberMeConfig.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder request = post("/login")
				.with(csrf())
				.param("username", "user")
				.param("password", "password")
				.param("remember-me", "true");
		// @formatter:on
		this.mvc.perform(request).andExpect(cookie().exists("remember-me"));
	}

	@Test
	public void getWhenRememberMeCookieThenAuthenticationIsRememberMeAuthenticationToken() throws Exception {
		this.spring.register(RememberMeConfig.class).autowire();
		MvcResult mvcResult = this.mvc.perform(post("/login").with(csrf()).param("username", "user")
				.param("password", "password").param("remember-me", "true")).andReturn();
		Cookie rememberMeCookie = mvcResult.getResponse().getCookie("remember-me");
		// @formatter:off
		MockHttpServletRequestBuilder request = get("/abc").cookie(rememberMeCookie);
		SecurityMockMvcResultMatchers.AuthenticatedMatcher remembermeAuthentication = authenticated()
				.withAuthentication((auth) -> assertThat(auth).isInstanceOf(RememberMeAuthenticationToken.class));
		// @formatter:on
		this.mvc.perform(request).andExpect(remembermeAuthentication);
	}

	@Test
	public void logoutWhenRememberMeCookieThenAuthenticationIsRememberMeCookieExpired() throws Exception {
		this.spring.register(RememberMeConfig.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder loginRequest = post("/login")
				.with(csrf())
				.param("username", "user")
				.param("password", "password")
				.param("remember-me", "true");
		// @formatter:on
		MvcResult mvcResult = this.mvc.perform(loginRequest).andReturn();
		Cookie rememberMeCookie = mvcResult.getResponse().getCookie("remember-me");
		HttpSession session = mvcResult.getRequest().getSession();
		// @formatter:off
		MockHttpServletRequestBuilder logoutRequest = post("/logout")
				.with(csrf())
				.cookie(rememberMeCookie)
				.session((MockHttpSession) session);
		this.mvc.perform(logoutRequest)
				.andExpect(redirectedUrl("/login?logout"))
				.andExpect(cookie().maxAge("remember-me", 0));
		// @formatter:on
	}

	@Test
	public void getWhenRememberMeCookieAndLoggedOutThenRedirectsToLogin() throws Exception {
		this.spring.register(RememberMeConfig.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder loginRequest = post("/login")
				.with(csrf())
				.param("username", "user")
				.param("password", "password")
				.param("remember-me", "true");
		// @formatter:on
		MvcResult loginMvcResult = this.mvc.perform(loginRequest).andReturn();
		Cookie rememberMeCookie = loginMvcResult.getResponse().getCookie("remember-me");
		HttpSession session = loginMvcResult.getRequest().getSession();
		// @formatter:off
		MockHttpServletRequestBuilder logoutRequest = post("/logout")
				.with(csrf())
				.cookie(rememberMeCookie)
				.session((MockHttpSession) session);
		// @formatter:on
		MvcResult logoutMvcResult = this.mvc.perform(logoutRequest).andReturn();
		Cookie expiredRememberMeCookie = logoutMvcResult.getResponse().getCookie("remember-me");
		// @formatter:off
		MockHttpServletRequestBuilder expiredRequest = get("/abc")
				.with(csrf())
				.cookie(expiredRememberMeCookie);
		// @formatter:on
		this.mvc.perform(expiredRequest).andExpect(redirectedUrl("http://localhost/login"));
	}

	@Test
	public void loginWhenRememberMeConfiguredInLambdaThenRespondsWithRememberMeCookie() throws Exception {
		this.spring.register(RememberMeInLambdaConfig.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder request = post("/login")
				.with(csrf())
				.param("username", "user")
				.param("password", "password")
				.param("remember-me", "true");
		// @formatter:on
		this.mvc.perform(request).andExpect(cookie().exists("remember-me"));
	}

	@Test
	public void loginWhenRememberMeTrueAndCookieDomainThenRememberMeCookieHasDomain() throws Exception {
		this.spring.register(RememberMeCookieDomainConfig.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder request = post("/login")
				.with(csrf())
				.param("username", "user")
				.param("password", "password")
				.param("remember-me", "true");
		this.mvc.perform(request).
				andExpect(cookie().exists("remember-me"))
				.andExpect(cookie().domain("remember-me", "spring.io"));
		// @formatter:on
	}

	@Test
	public void loginWhenRememberMeTrueAndCookieDomainInLambdaThenRememberMeCookieHasDomain() throws Exception {
		this.spring.register(RememberMeCookieDomainInLambdaConfig.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder loginRequest = post("/login")
				.with(csrf())
				.param("username", "user")
				.param("password", "password")
				.param("remember-me", "true");
		this.mvc.perform(loginRequest)
				.andExpect(cookie().exists("remember-me"))
				.andExpect(cookie().domain("remember-me", "spring.io"));
		// @formatter:on
	}

	@Test
	public void configureWhenRememberMeCookieNameAndRememberMeServicesThenException() {
		assertThatExceptionOfType(BeanCreationException.class)
				.isThrownBy(
						() -> this.spring.register(RememberMeCookieNameAndRememberMeServicesConfig.class).autowire())
				.withRootCauseInstanceOf(IllegalArgumentException.class)
				.withMessageContaining("Can not set rememberMeCookieName and custom rememberMeServices.");
	}

	@Test
	public void getWhenRememberMeCookieAndNoKeyConfiguredThenKeyFromRememberMeServicesIsUsed() throws Exception {
		this.spring.register(FallbackRememberMeKeyConfig.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder loginRequest = post("/login")
				.with(csrf())
				.param("username", "user")
				.param("password", "password")
				.param("remember-me", "true");
		// @formatter:on
		MvcResult mvcResult = this.mvc.perform(loginRequest).andReturn();
		Cookie rememberMeCookie = mvcResult.getResponse().getCookie("remember-me");
		MockHttpServletRequestBuilder requestWithRememberme = get("/abc").cookie(rememberMeCookie);
		// @formatter:off
		SecurityMockMvcResultMatchers.AuthenticatedMatcher remembermeAuthentication = authenticated()
				.withAuthentication((auth) -> assertThat(auth).isInstanceOf(RememberMeAuthenticationToken.class));
		// @formatter:on
		this.mvc.perform(requestWithRememberme).andExpect(remembermeAuthentication);
	}

	@Configuration
	@EnableWebSecurity
	static class NullUserDetailsConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.formLogin()
					.and()
				.rememberMe();
			// @formatter:on
			return http.build();
		}

		@Autowired
		void configure(AuthenticationManagerBuilder auth) {
			User user = (User) PasswordEncodedUser.user();
			DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
			provider.setUserDetailsService(new InMemoryUserDetailsManager(Collections.singletonList(user)));
			// @formatter:off
			auth
				.authenticationProvider(provider);
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class ObjectPostProcessorConfig {

		ObjectPostProcessor<Object> objectPostProcessor = spy(ReflectingObjectPostProcessor.class);

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.rememberMe()
					.userDetailsService(new AuthenticationManagerBuilder(this.objectPostProcessor).getDefaultUserDetailsService());
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager();
		}

		@Bean
		ObjectPostProcessor<Object> objectPostProcessor() {
			return this.objectPostProcessor;
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

		static UserDetailsService userDetailsService = mock(UserDetailsService.class);

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic()
					.and()
				.rememberMe()
					.userDetailsService(userDetailsService)
					.and()
				.rememberMe();
			return http.build();
			// @formatter:on
		}

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

	@Configuration
	@EnableWebSecurity
	static class UserDetailsServiceBeanConfig {

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.formLogin(withDefaults())
				.rememberMe(withDefaults());
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService customUserDetailsService() {
			return new InMemoryUserDetailsManager(PasswordEncodedUser.user());
		}

	}

	@Configuration
	@EnableWebSecurity
	static class RememberMeConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.formLogin()
					.and()
				.rememberMe();
			return http.build();
			// @formatter:on
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(PasswordEncodedUser.user());
		}

	}

	@Configuration
	@EnableWebSecurity
	static class RememberMeInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests((authorizeRequests) ->
					authorizeRequests
						.anyRequest().hasRole("USER")
				)
				.formLogin(withDefaults())
				.rememberMe(withDefaults());
			return http.build();
			// @formatter:on
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(PasswordEncodedUser.user());
		}

	}

	@Configuration
	@EnableWebSecurity
	static class RememberMeCookieDomainConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.formLogin()
					.and()
				.rememberMe()
					.rememberMeCookieDomain("spring.io");
			return http.build();
			// @formatter:on
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(PasswordEncodedUser.user());
		}

	}

	@Configuration
	@EnableWebSecurity
	static class RememberMeCookieDomainInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests((authorizeRequests) ->
					authorizeRequests
						.anyRequest().hasRole("USER")
				)
				.formLogin(withDefaults())
				.rememberMe((rememberMe) ->
					rememberMe
						.rememberMeCookieDomain("spring.io")
				);
			return http.build();
			// @formatter:on
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(PasswordEncodedUser.user());
		}

	}

	@Configuration
	@EnableWebSecurity
	static class RememberMeCookieNameAndRememberMeServicesConfig {

		static RememberMeServices REMEMBER_ME = mock(RememberMeServices.class);

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.formLogin()
					.and()
				.rememberMe()
					.rememberMeCookieName("SPRING_COOKIE_DOMAIN")
					.rememberMeCookieDomain("spring.io")
					.rememberMeServices(REMEMBER_ME);
			return http.build();
			// @formatter:on
		}

		@Autowired
		void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user());
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class FallbackRememberMeKeyConfig extends RememberMeConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.formLogin()
					.and()
				.rememberMe()
					.rememberMeServices(new TokenBasedRememberMeServices("key", userDetailsService()));
			return http.build();
			// @formatter:on
		}

	}

}
