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

package org.springframework.security.config.annotation.web.configurers;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.ui.DefaultResourcesFilter;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Daniel Garnier-Moiroux
 */
@ExtendWith(SpringTestContextExtension.class)
public class WebAuthnConfigurerTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	@Test
	public void webauthnWhenConfiguredConfiguredThenServesJavascript() throws Exception {
		this.spring.register(DefaultWebauthnConfiguration.class).autowire();
		this.mvc.perform(get("/login/webauthn.js"))
			.andExpect(status().isOk())
			.andExpect(header().string("content-type", "text/javascript;charset=UTF-8"))
			.andExpect(content().string(containsString("async function authenticate(")));
	}

	@Test
	public void webauthnWhenConfiguredConfiguredThenServesCss() throws Exception {
		this.spring.register(DefaultWebauthnConfiguration.class).autowire();
		this.mvc.perform(get("/default-ui.css"))
			.andExpect(status().isOk())
			.andExpect(header().string("content-type", "text/css;charset=UTF-8"))
			.andExpect(content().string(containsString("body {")));
	}

	@Test
	public void webauthnWhenNoFormLoginAndDefaultRegistrationPageConfiguredThenServesJavascript() throws Exception {
		this.spring.register(NoFormLoginAndDefaultRegistrationPageConfiguration.class).autowire();
		this.mvc.perform(get("/login/webauthn.js"))
			.andExpect(status().isOk())
			.andExpect(header().string("content-type", "text/javascript;charset=UTF-8"))
			.andExpect(content().string(containsString("async function authenticate(")));
	}

	@Test
	public void webauthnWhenNoFormLoginAndDefaultRegistrationPageConfiguredThenServesCss() throws Exception {
		this.spring.register(NoFormLoginAndDefaultRegistrationPageConfiguration.class).autowire();
		this.mvc.perform(get("/default-ui.css"))
			.andExpect(status().isOk())
			.andExpect(header().string("content-type", "text/css;charset=UTF-8"))
			.andExpect(content().string(containsString("body {")));
	}

	@Test
	public void webauthnWhenFormLoginAndDefaultRegistrationPageConfiguredThenNoDuplicateFilters() {
		this.spring.register(DefaultWebauthnConfiguration.class).autowire();
		FilterChainProxy filterChain = this.spring.getContext().getBean(FilterChainProxy.class);

		List<DefaultResourcesFilter> defaultResourcesFilters = filterChain.getFilterChains()
			.get(0)
			.getFilters()
			.stream()
			.filter(DefaultResourcesFilter.class::isInstance)
			.map(DefaultResourcesFilter.class::cast)
			.toList();

		assertThat(defaultResourcesFilters).map(DefaultResourcesFilter::toString)
			.filteredOn((filterDescription) -> filterDescription.contains("login/webauthn.js"))
			.hasSize(1);
		assertThat(defaultResourcesFilters).map(DefaultResourcesFilter::toString)
			.filteredOn((filterDescription) -> filterDescription.contains("default-ui.css"))
			.hasSize(1);
	}

	@Test
	public void webauthnWhenConfiguredAndFormLoginThenDoesServesJavascript() throws Exception {
		this.spring.register(FormLoginAndNoDefaultRegistrationPageConfiguration.class).autowire();
		this.mvc.perform(get("/login/webauthn.js"))
			.andExpect(status().isOk())
			.andExpect(header().string("content-type", "text/javascript;charset=UTF-8"))
			.andExpect(content().string(containsString("async function authenticate(")));
	}

	@Test
	public void webauthnWhenConfiguredAndNoDefaultRegistrationPageThenDoesNotServeJavascript() throws Exception {
		this.spring.register(NoDefaultRegistrationPageConfiguration.class).autowire();
		this.mvc.perform(get("/login/webauthn.js")).andExpect(status().isNotFound());
	}

	@Configuration
	@EnableWebSecurity
	static class DefaultWebauthnConfiguration {

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager();
		}

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			return http.formLogin(Customizer.withDefaults()).webAuthn(Customizer.withDefaults()).build();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class NoFormLoginAndDefaultRegistrationPageConfiguration {

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager();
		}

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			return http.webAuthn(Customizer.withDefaults()).build();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class FormLoginAndNoDefaultRegistrationPageConfiguration {

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager();
		}

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			return http.formLogin(Customizer.withDefaults())
				.webAuthn((webauthn) -> webauthn.disableDefaultRegistrationPage(true))
				.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class NoDefaultRegistrationPageConfiguration {

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager();
		}

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			return http.formLogin((login) -> login.loginPage("/custom-login-page"))
				.webAuthn((webauthn) -> webauthn.disableDefaultRegistrationPage(true))
				.build();
		}

	}

}
