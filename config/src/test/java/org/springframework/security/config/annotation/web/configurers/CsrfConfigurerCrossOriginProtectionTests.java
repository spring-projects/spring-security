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

import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.csrf.CrossOriginProtectionFilter;
import org.springframework.security.web.csrf.CsrfException;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link CsrfConfigurer#crossOriginProtection(Customizer)}.
 *
 * @author Scott Murphy Heiberg
 */
@ExtendWith(SpringTestContextExtension.class)
public class CsrfConfigurerCrossOriginProtectionTests {

	@Autowired
	MockMvc mvc;

	public final SpringTestContext spring = new SpringTestContext(this);

	@Test
	public void postWhenCrossSiteThenForbidden() throws Exception {
		this.spring.register(CrossOriginProtectionConfig.class, BasicController.class).autowire();
		this.mvc.perform(post("/path").header("Sec-Fetch-Site", "cross-site")).andExpect(status().isForbidden());
		this.mvc.perform(post("/path").header("Sec-Fetch-Site", "same-site")).andExpect(status().isForbidden());
	}

	@Test
	public void postWhenSameOriginThenOkWithoutToken() throws Exception {
		this.spring.register(CrossOriginProtectionConfig.class, BasicController.class).autowire();
		this.mvc.perform(post("/path").header("Sec-Fetch-Site", "same-origin")).andExpect(status().isOk());
	}

	@Test
	public void postWhenNotFromBrowserThenOkWithoutToken() throws Exception {
		this.spring.register(CrossOriginProtectionConfig.class, BasicController.class).autowire();
		this.mvc.perform(post("/path")).andExpect(status().isOk());
	}

	@Test
	public void postWhenOriginOnlyThenComparedWithRequestOrigin() throws Exception {
		this.spring.register(CrossOriginProtectionConfig.class, BasicController.class).autowire();
		this.mvc.perform(post("/path").header("Origin", "http://localhost")).andExpect(status().isOk());
		this.mvc.perform(post("/path").header("Origin", "https://evil.example")).andExpect(status().isForbidden());
	}

	@Test
	public void getWhenCrossSiteThenOk() throws Exception {
		this.spring.register(CrossOriginProtectionConfig.class, BasicController.class).autowire();
		this.mvc.perform(get("/path").header("Sec-Fetch-Site", "cross-site")).andExpect(status().isOk());
	}

	@Test
	public void postWhenCrossSiteAndIgnoredThenOk() throws Exception {
		this.spring.register(IgnoringRequestMatchersConfig.class, BasicController.class).autowire();
		this.mvc.perform(post("/hooks/payment").header("Sec-Fetch-Site", "cross-site")).andExpect(status().isOk());
		this.mvc.perform(post("/path").header("Sec-Fetch-Site", "cross-site")).andExpect(status().isForbidden());
	}

	@Test
	public void postWhenCrossSiteFromTrustedOriginThenOk() throws Exception {
		this.spring.register(TrustedOriginsConfig.class, BasicController.class).autowire();
		this.mvc
			.perform(post("/path").header("Sec-Fetch-Site", "cross-site").header("Origin", "https://partner.example"))
			.andExpect(status().isOk());
		this.mvc.perform(post("/path").header("Sec-Fetch-Site", "cross-site").header("Origin", "https://evil.example"))
			.andExpect(status().isForbidden());
	}

	@Test
	public void postWhenCrossSiteThenExceptionHandlingAccessDeniedHandlerUsed() throws Exception {
		this.spring.register(AccessDeniedHandlerConfig.class, BasicController.class).autowire();
		this.mvc.perform(post("/path").header("Sec-Fetch-Site", "cross-site"))
			.andExpect(status().is(HttpStatus.I_AM_A_TEAPOT.value()));
		verify(AccessDeniedHandlerConfig.handler).handle(any(), any(), any(CsrfException.class));
	}

	@Test
	public void requestWhenCrossOriginProtectionThenNoTokenAndNoSession() throws Exception {
		this.spring.register(CrossOriginProtectionConfig.class, BasicController.class).autowire();
		MvcResult result = this.mvc.perform(get("/path")).andExpect(status().isOk()).andReturn();
		assertThat(result.getRequest().getAttribute(CsrfToken.class.getName())).isNull();
		assertThat(result.getRequest().getSession(false)).isNull();
	}

	@Test
	public void filterChainWhenCrossOriginProtectionThenCrossOriginProtectionFilterInsteadOfCsrfFilter() {
		this.spring.register(CrossOriginProtectionConfig.class, BasicController.class).autowire();
		FilterChainProxy filterChainProxy = this.spring.getContext().getBean(FilterChainProxy.class);
		assertThat(filterChainProxy.getFilters("/path")).map(Filter::getClass)
			.contains(CrossOriginProtectionFilter.class)
			.doesNotContain(CsrfFilter.class);
	}

	@Test
	public void logoutWhenGetThenSessionKept() throws Exception {
		this.spring.register(CrossOriginProtectionConfig.class, BasicController.class).autowire();
		MockHttpSession session = new MockHttpSession();
		this.mvc.perform(get("/logout").session(session));
		assertThat(session.isInvalid()).isFalse();
		this.mvc.perform(post("/logout").session(session).header("Sec-Fetch-Site", "cross-site"))
			.andExpect(status().isForbidden());
		assertThat(session.isInvalid()).isFalse();
		this.mvc.perform(post("/logout").session(session).header("Sec-Fetch-Site", "same-origin"))
			.andExpect(status().is3xxRedirection());
		assertThat(session.isInvalid()).isTrue();
	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	static class CrossOriginProtectionConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.csrf((csrf) -> csrf
					.crossOriginProtection(Customizer.withDefaults()))
				.logout(Customizer.withDefaults());
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	static class IgnoringRequestMatchersConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.csrf((csrf) -> csrf
					.crossOriginProtection(Customizer.withDefaults())
					.ignoringRequestMatchers("/hooks/**"));
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	static class TrustedOriginsConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.csrf((csrf) -> csrf
					.crossOriginProtection((crossOrigin) -> crossOrigin
						.trustedOrigins("https://partner.example")));
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	static class AccessDeniedHandlerConfig {

		static AccessDeniedHandler handler = mock(AccessDeniedHandler.class, (invocation) -> {
			invocation.<HttpServletResponse>getArgument(1).setStatus(HttpStatus.I_AM_A_TEAPOT.value());
			return null;
		});

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.csrf((csrf) -> csrf
					.crossOriginProtection(Customizer.withDefaults()))
				.exceptionHandling((exceptions) -> exceptions
					.accessDeniedHandler(handler));
			return http.build();
			// @formatter:on
		}

	}

	@RestController
	public static class BasicController {

		@RequestMapping("/path")
		public String path() {
			return "path";
		}

		@RequestMapping("/hooks/payment")
		public String payment() {
			return "payment";
		}

	}

}
