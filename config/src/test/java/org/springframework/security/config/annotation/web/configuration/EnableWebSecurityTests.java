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

package org.springframework.security.config.annotation.web.configuration;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
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
@ExtendWith(SpringTestContextExtension.class)
public class EnableWebSecurityTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	private MockMvc mockMvc;

	@Test
	public void loadConfigWhenChildConfigExtendsSecurityConfigThenSecurityConfigInherited() {
		this.spring.register(ChildSecurityConfig.class).autowire();
		this.spring.getContext().getBean("springSecurityFilterChain", DebugFilter.class);
	}

	@Test
	public void configureWhenEnableWebMvcThenAuthenticationPrincipalResolvable() throws Exception {
		this.spring.register(AuthenticationPrincipalConfig.class).autowire();
		this.mockMvc.perform(get("/").with(authentication(new TestingAuthenticationToken("user1", "password"))))
				.andExpect(content().string("user1"));
	}

	@Test
	public void securityFilterChainWhenEnableWebMvcThenAuthenticationPrincipalResolvable() throws Exception {
		this.spring.register(SecurityFilterChainAuthenticationPrincipalConfig.class).autowire();
		this.mockMvc.perform(get("/").with(authentication(new TestingAuthenticationToken("user1", "password"))))
				.andExpect(content().string("user1"));
	}

	@Test
	public void enableWebSecurityWhenNoConfigurationAnnotationThenBeanProxyingEnabled() {
		this.spring.register(BeanProxyEnabledByDefaultConfig.class).autowire();
		Child childBean = this.spring.getContext().getBean(Child.class);
		Parent parentBean = this.spring.getContext().getBean(Parent.class);
		assertThat(parentBean.getChild()).isSameAs(childBean);
	}

	@Test
	public void enableWebSecurityWhenProxyBeanMethodsFalseThenBeanProxyingDisabled() {
		this.spring.register(BeanProxyDisabledConfig.class).autowire();
		Child childBean = this.spring.getContext().getBean(Child.class);
		Parent parentBean = this.spring.getContext().getBean(Parent.class);
		assertThat(parentBean.getChild()).isNotSameAs(childBean);
	}

	@Configuration
	static class ChildSecurityConfig extends DebugSecurityConfig {

	}

	@Configuration
	@EnableWebSecurity(debug = true)
	static class DebugSecurityConfig {

	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	static class AuthenticationPrincipalConfig {

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

	@Configuration
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

	@Configuration
	@EnableWebSecurity
	static class BeanProxyEnabledByDefaultConfig {

		@Bean
		Child child() {
			return new Child();
		}

		@Bean
		Parent parent() {
			return new Parent(child());
		}

	}

	@Configuration(proxyBeanMethods = false)
	@EnableWebSecurity
	static class BeanProxyDisabledConfig {

		@Bean
		Child child() {
			return new Child();
		}

		@Bean
		Parent parent() {
			return new Parent(child());
		}

	}

	static class Parent {

		private Child child;

		Parent(Child child) {
			this.child = child;
		}

		Child getChild() {
			return this.child;
		}

	}

	static class Child {

		Child() {
		}

	}

}
