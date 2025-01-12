/*
 * Copyright 2002-2025 the original author or authors.
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

import java.io.IOException;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.ui.DefaultResourcesFilter;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.api.TestPublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.management.WebAuthnRelyingPartyOperations;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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

	@Test
	public void webauthnWhenConfiguredMessageConverter() throws Exception {
		TestingAuthenticationToken user = new TestingAuthenticationToken("user", "password", "ROLE_USER");
		SecurityContextHolder.setContext(new SecurityContextImpl(user));
		PublicKeyCredentialCreationOptions options = TestPublicKeyCredentialCreationOptions
			.createPublicKeyCredentialCreationOptions()
			.build();
		WebAuthnRelyingPartyOperations rpOperations = mock(WebAuthnRelyingPartyOperations.class);
		ConfigMessageConverter.rpOperations = rpOperations;
		given(rpOperations.createPublicKeyCredentialCreationOptions(any())).willReturn(options);
		HttpMessageConverter<Object> converter = new AbstractHttpMessageConverter<>() {
			@Override
			protected boolean supports(Class<?> clazz) {
				return true;
			}

			@Override
			protected Object readInternal(Class<?> clazz, HttpInputMessage inputMessage)
					throws IOException, HttpMessageNotReadableException {
				return null;
			}

			@Override
			protected void writeInternal(Object o, HttpOutputMessage outputMessage)
					throws IOException, HttpMessageNotWritableException {
				outputMessage.getBody().write("123".getBytes());
			}
		};
		ConfigMessageConverter.converter = converter;
		this.spring.register(ConfigMessageConverter.class).autowire();
		this.mvc.perform(post("/webauthn/register/options"))
			.andExpect(status().isOk())
			.andExpect(content().string("123"));
	}

	@Configuration
	@EnableWebSecurity
	static class ConfigMessageConverter {

		private static HttpMessageConverter<Object> converter;

		private static WebAuthnRelyingPartyOperations rpOperations;

		@Bean
		WebAuthnRelyingPartyOperations webAuthnRelyingPartyOperations() {
			return ConfigMessageConverter.rpOperations;
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager();
		}

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			return http.csrf(AbstractHttpConfigurer::disable).webAuthn((c) -> c.messageConverter(converter)).build();
		}

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
