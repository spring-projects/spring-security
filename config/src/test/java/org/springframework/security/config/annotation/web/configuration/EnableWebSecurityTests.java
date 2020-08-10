/*
 * Copyright 2002-2020 the original author or authors.
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

import org.junit.Rule;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.debug.DebugFilter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;

/**
 * @author Joe Grandja
 */
public class EnableWebSecurityTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MockMvc mockMvc;

	@Test
	public void configureWhenOverrideAuthenticationManagerBeanThenAuthenticationManagerBeanRegistered() {
		this.spring.register(SecurityConfig.class).autowire();

		AuthenticationManager authenticationManager = this.spring.getContext().getBean(AuthenticationManager.class);
		Authentication authentication = authenticationManager
				.authenticate(new UsernamePasswordAuthenticationToken("user", "password"));
		assertThat(authentication.isAuthenticated()).isTrue();
	}

	@EnableWebSecurity
	static class SecurityConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user());
			// @formatter:on
		}

		@Bean
		@Override
		public AuthenticationManager authenticationManagerBean() throws Exception {
			return super.authenticationManagerBean();
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.antMatchers("/*").hasRole("USER")
					.and()
				.formLogin();
			// @formatter:on
		}

	}

	@Test
	public void loadConfigWhenChildConfigExtendsSecurityConfigThenSecurityConfigInherited() {
		this.spring.register(ChildSecurityConfig.class).autowire();
		this.spring.getContext().getBean("springSecurityFilterChain", DebugFilter.class);
	}

	@Configuration
	static class ChildSecurityConfig extends DebugSecurityConfig {

	}

	@EnableWebSecurity(debug = true)
	static class DebugSecurityConfig extends WebSecurityConfigurerAdapter {

	}

	@Test
	public void configureWhenEnableWebMvcThenAuthenticationPrincipalResolvable() throws Exception {
		this.spring.register(AuthenticationPrincipalConfig.class).autowire();

		this.mockMvc.perform(get("/").with(authentication(new TestingAuthenticationToken("user1", "password"))))
				.andExpect(content().string("user1"));
	}

	@EnableWebSecurity
	@EnableWebMvc
	static class AuthenticationPrincipalConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) {
		}

		@RestController
		static class AuthController {

			@GetMapping("/")
			String principal(@AuthenticationPrincipal String principal) {
				return principal;
			}

		}

	}

	@Test
	public void securityFilterChainWhenEnableWebMvcThenAuthenticationPrincipalResolvable() throws Exception {
		this.spring.register(SecurityFilterChainAuthenticationPrincipalConfig.class).autowire();

		this.mockMvc.perform(get("/").with(authentication(new TestingAuthenticationToken("user1", "password"))))
				.andExpect(content().string("user1"));
	}

	@EnableWebSecurity
	@EnableWebMvc
	static class SecurityFilterChainAuthenticationPrincipalConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			return http.build();
		}

		@RestController
		static class AuthController {

			@GetMapping("/")
			String principal(@AuthenticationPrincipal String principal) {
				return principal;
			}

		}

	}

	@Test
	public void enableWebSecurityWhenNoConfigurationAnnotationThenBeanProxyingEnabled() {
		this.spring.register(BeanProxyEnabledByDefaultConfig.class).autowire();

		Child childBean = this.spring.getContext().getBean(Child.class);
		Parent parentBean = this.spring.getContext().getBean(Parent.class);

		assertThat(parentBean.getChild()).isSameAs(childBean);
	}

	@EnableWebSecurity
	static class BeanProxyEnabledByDefaultConfig extends WebSecurityConfigurerAdapter {

		@Bean
		public Child child() {
			return new Child();
		}

		@Bean
		public Parent parent() {
			return new Parent(child());
		}

	}

	@Test
	public void enableWebSecurityWhenProxyBeanMethodsFalseThenBeanProxyingDisabled() {
		this.spring.register(BeanProxyDisabledConfig.class).autowire();

		Child childBean = this.spring.getContext().getBean(Child.class);
		Parent parentBean = this.spring.getContext().getBean(Parent.class);

		assertThat(parentBean.getChild()).isNotSameAs(childBean);
	}

	@Configuration(proxyBeanMethods = false)
	@EnableWebSecurity
	static class BeanProxyDisabledConfig extends WebSecurityConfigurerAdapter {

		@Bean
		public Child child() {
			return new Child();
		}

		@Bean
		public Parent parent() {
			return new Parent(child());
		}

	}

	static class Parent {

		private Child child;

		Parent(Child child) {
			this.child = child;
		}

		public Child getChild() {
			return child;
		}

	}

	static class Child {

		Child() {
		}

	}

}
