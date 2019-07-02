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
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpSession;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
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
	public void postWhenNoUserDetailsServiceThenException() throws Exception {
		this.spring.register(NullUserDetailsConfig.class).autowire();

		assertThatThrownBy(() ->
				mvc.perform(post("/login")
						.param("username", "user")
						.param("password", "password")
						.param("remember-me", "true")
						.with(csrf())))
				.hasMessageContaining("UserDetailsService is required");
	}

	@EnableWebSecurity
	static class NullUserDetailsConfig extends WebSecurityConfigurerAdapter {
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
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			User user = (User) PasswordEncodedUser.user();
			DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
			provider.setUserDetailsService(new InMemoryUserDetailsManager(Collections.singletonList(user)));
			// @formatter:off
			auth
				.authenticationProvider(provider);
			// @formatter:on
		}
	}

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnRememberMeAuthenticationFilter() {
		this.spring.register(ObjectPostProcessorConfig.class).autowire();

		verify(ObjectPostProcessorConfig.objectPostProcessor)
				.postProcess(any(RememberMeAuthenticationFilter.class));
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

	@Test
	public void rememberMeWhenInvokedTwiceThenUsesOriginalUserDetailsService() throws Exception {
		when(DuplicateDoesNotOverrideConfig.userDetailsService.loadUserByUsername(anyString()))
				.thenReturn(new User("user", "password", Collections.emptyList()));
		this.spring.register(DuplicateDoesNotOverrideConfig.class).autowire();

		this.mvc.perform(get("/")
				.with(httpBasic("user", "password"))
				.param("remember-me", "true"));

		verify(DuplicateDoesNotOverrideConfig.userDetailsService).loadUserByUsername("user");
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

		@Bean
		public UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(
					User.withDefaultPasswordEncoder()
							.username("user")
							.password("password")
							.roles("USER")
							.build()
			);
		}
	}

	@Test
	public void loginWhenRememberMeTrueThenRespondsWithRememberMeCookie() throws Exception {
		this.spring.register(RememberMeConfig.class).autowire();

		this.mvc.perform(post("/login")
				.with(csrf())
				.param("username", "user")
				.param("password", "password")
				.param("remember-me", "true"))
				.andExpect(cookie().exists("remember-me"));
	}

	@Test
	public void getWhenRememberMeCookieThenAuthenticationIsRememberMeAuthenticationToken() throws Exception {
		this.spring.register(RememberMeConfig.class).autowire();

		MvcResult mvcResult = this.mvc.perform(post("/login")
				.with(csrf())
				.param("username", "user")
				.param("password", "password")
				.param("remember-me", "true"))
				.andReturn();
		Cookie rememberMeCookie = mvcResult.getResponse().getCookie("remember-me");

		this.mvc.perform(get("/abc")
				.cookie(rememberMeCookie))
				.andExpect(authenticated().withAuthentication(auth ->
						assertThat(auth).isInstanceOf(RememberMeAuthenticationToken.class)));
	}

	@Test
	public void logoutWhenRememberMeCookieThenAuthenticationIsRememberMeCookieExpired() throws Exception {
		this.spring.register(RememberMeConfig.class).autowire();

		MvcResult mvcResult = this.mvc.perform(post("/login")
				.with(csrf())
				.param("username", "user")
				.param("password", "password")
				.param("remember-me", "true"))
				.andReturn();
		Cookie rememberMeCookie = mvcResult.getResponse().getCookie("remember-me");
		HttpSession session = mvcResult.getRequest().getSession();

		this.mvc.perform(post("/logout")
				.with(csrf())
				.cookie(rememberMeCookie)
				.session((MockHttpSession) session))
				.andExpect(redirectedUrl("/login?logout"))
				.andExpect(cookie().maxAge("remember-me", 0));
	}

	@Test
	public void getWhenRememberMeCookieAndLoggedOutThenRedirectsToLogin() throws Exception {
		this.spring.register(RememberMeConfig.class).autowire();

		MvcResult loginMvcResult = this.mvc.perform(post("/login")
				.with(csrf())
				.param("username", "user")
				.param("password", "password")
				.param("remember-me", "true"))
				.andReturn();
		Cookie rememberMeCookie = loginMvcResult.getResponse().getCookie("remember-me");
		HttpSession session = loginMvcResult.getRequest().getSession();
		MvcResult logoutMvcResult = this.mvc.perform(post("/logout")
				.with(csrf())
				.cookie(rememberMeCookie)
				.session((MockHttpSession) session))
				.andReturn();
		Cookie expiredRememberMeCookie = logoutMvcResult.getResponse().getCookie("remember-me");

		this.mvc.perform(get("/abc")
				.with(csrf())
				.cookie(expiredRememberMeCookie))
				.andExpect(redirectedUrl("http://localhost/login"));
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
		public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user());
			// @formatter:on
		}
	}


	@Test
	public void loginWhenRememberMeConfiguredInLambdaThenRespondsWithRememberMeCookie() throws Exception {
		this.spring.register(RememberMeInLambdaConfig.class).autowire();

		this.mvc.perform(post("/login")
				.with(csrf())
				.param("username", "user")
				.param("password", "password")
				.param("remember-me", "true"))
				.andExpect(cookie().exists("remember-me"));
	}

	@EnableWebSecurity
	static class RememberMeInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.formLogin(withDefaults())
				.rememberMe(withDefaults());
			// @formatter:on
		}

		@Autowired
		public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user());
			// @formatter:on
		}
	}

	@Test
	public void loginWhenRememberMeTrueAndCookieDomainThenRememberMeCookieHasDomain() throws Exception {
		this.spring.register(RememberMeCookieDomainConfig.class).autowire();

		this.mvc.perform(post("/login")
				.with(csrf())
				.param("username", "user")
				.param("password", "password")
				.param("remember-me", "true"))
				.andExpect(cookie().exists("remember-me"))
				.andExpect(cookie().domain("remember-me", "spring.io"));
	}

	@EnableWebSecurity
	static class RememberMeCookieDomainConfig extends WebSecurityConfigurerAdapter {
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
		public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user());
			// @formatter:on
		}
	}

	@Test
	public void loginWhenRememberMeTrueAndCookieDomainInLambdaThenRememberMeCookieHasDomain() throws Exception {
		this.spring.register(RememberMeCookieDomainInLambdaConfig.class).autowire();

		this.mvc.perform(post("/login")
				.with(csrf())
				.param("username", "user")
				.param("password", "password")
				.param("remember-me", "true"))
				.andExpect(cookie().exists("remember-me"))
				.andExpect(cookie().domain("remember-me", "spring.io"));
	}

	@EnableWebSecurity
	static class RememberMeCookieDomainInLambdaConfig extends WebSecurityConfigurerAdapter {
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.formLogin(withDefaults())
				.rememberMe(rememberMe ->
					rememberMe
						.rememberMeCookieDomain("spring.io")
				);
			// @formatter:on
		}

		@Autowired
		public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user());
			// @formatter:on
		}
	}

	@Test
	public void configureWhenRememberMeCookieNameAndRememberMeServicesThenException() {
		assertThatThrownBy(() -> this.spring.register(RememberMeCookieNameAndRememberMeServicesConfig.class).autowire())
				.isInstanceOf(BeanCreationException.class)
				.hasRootCauseInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("Can not set rememberMeCookieName and custom rememberMeServices.");
	}

	@EnableWebSecurity
	static class RememberMeCookieNameAndRememberMeServicesConfig extends WebSecurityConfigurerAdapter {
		static RememberMeServices REMEMBER_ME = mock(RememberMeServices.class);

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
		public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user());
			// @formatter:on
		}
	}
}
