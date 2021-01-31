/*
 * Copyright 2002-2021 the original author or authors.
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

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpSession;

import org.apache.commons.codec.binary.Base64;
import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.RememberMeHashingAlgorithm;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
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
public class RememberMeConfigurerTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	@Test
	public void postWhenNoUserDetailsServiceThenException() {
		this.spring.register(NullUserDetailsConfig.class).autowire();
		assertThatIllegalStateException().isThrownBy(() -> {
			// @formatter:off
					MockHttpServletRequestBuilder request = post("/login")
							.param("username", "user")
							.param("password", "password")
							.param("remember-me", "true")
							.with(csrf());
					// @formatter:on
			this.mvc.perform(request);
		}).withMessageContaining("UserDetailsService is required");
	}

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnRememberMeAuthenticationFilter() {
		this.spring.register(ObjectPostProcessorConfig.class).autowire();
		verify(ObjectPostProcessorConfig.objectPostProcessor).postProcess(any(RememberMeAuthenticationFilter.class));
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
	public void loginWithSha256HashingAlgorithmThenRespondsWithSha256RememberMeCookie() throws Exception {
		this.spring.register(RememberMeWithSha256Config.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder request = post("/login")
				.with(csrf())
				.param("username", "user")
				.param("password", "password")
				.param("remember-me", "true");
		// @formatter:on
		MvcResult result = this.mvc.perform(request).andReturn();
		Cookie rememberMe = result.getResponse().getCookie("remember-me");
		assertThat(rememberMe).isNotNull();
		assertThat(new String(Base64.decodeBase64(rememberMe.getValue())))
				.contains(RememberMeHashingAlgorithm.SHA256.getIdentifier());
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

	@EnableWebSecurity
	static class NullUserDetailsConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.formLogin()
					.and()
				.rememberMe();
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) {
			User user = (User) PasswordEncodedUser.user();
			DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
			provider.setUserDetailsService(new InMemoryUserDetailsManager(Collections.singletonList(user)));
			// @formatter:off
			auth
				.authenticationProvider(provider);
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class ObjectPostProcessorConfig extends WebSecurityConfigurerAdapter {

		static ObjectPostProcessor<Object> objectPostProcessor = spy(ReflectingObjectPostProcessor.class);

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.rememberMe()
					.userDetailsService(new AuthenticationManagerBuilder(objectPostProcessor).getDefaultUserDetailsService());
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication();
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

		static UserDetailsService userDetailsService = mock(UserDetailsService.class);

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic()
					.and()
				.rememberMe()
					.userDetailsService(userDetailsService)
					.and()
				.rememberMe();
			// @formatter:on
		}

		@Override
		@Bean
		public UserDetailsService userDetailsService() {
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

	@EnableWebSecurity
	static class RememberMeConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.formLogin()
					.and()
				.rememberMe();
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

	@EnableWebSecurity
	static class RememberMeWithSha256Config extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.authorizeRequests()
						.anyRequest().hasRole("USER")
						.and()
					.formLogin()
						.and()
					.rememberMe()
						.hashingAlgorithm(RememberMeHashingAlgorithm.SHA256);
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

	@EnableWebSecurity
	static class RememberMeInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests((authorizeRequests) ->
					authorizeRequests
						.anyRequest().hasRole("USER")
				)
				.formLogin(withDefaults())
				.rememberMe(withDefaults());
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

	@EnableWebSecurity
	static class RememberMeCookieDomainConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.formLogin()
					.and()
				.rememberMe()
					.rememberMeCookieDomain("spring.io");
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

	@EnableWebSecurity
	static class RememberMeCookieDomainInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
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

	@EnableWebSecurity
	static class RememberMeCookieNameAndRememberMeServicesConfig extends WebSecurityConfigurerAdapter {

		static RememberMeServices REMEMBER_ME = mock(RememberMeServices.class);

		@Override
		protected void configure(HttpSecurity http) throws Exception {
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

	@EnableWebSecurity
	static class FallbackRememberMeKeyConfig extends RememberMeConfig {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			super.configure(http);
			// @formatter:off
			http.rememberMe()
					.rememberMeServices(new TokenBasedRememberMeServices("key", userDetailsService()));
			// @formatter:on
		}

	}

}
