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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRequestHandler;
import org.springframework.security.web.csrf.DeferredCsrfToken;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.web.servlet.TestMockHttpServletRequests.post;

/**
 * @author Rob Winch
 */
public class SessionManagementConfigurerServlet31Tests {

	MockHttpServletResponse response;

	MockFilterChain chain;

	ConfigurableApplicationContext context;

	Filter springSecurityFilterChain;

	@BeforeEach
	public void setup() {
		this.response = new MockHttpServletResponse();
		this.chain = new MockFilterChain();
	}

	@AfterEach
	public void teardown() {
		if (this.context != null) {
			this.context.close();
		}
	}

	@Test
	public void changeSessionIdThenPreserveParameters() throws Exception {
		MockHttpServletRequest request = post("/login").param("username", "user").param("password", "password").build();
		String id = request.getSession().getId();
		request.getSession();
		HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
		CsrfTokenRequestHandler handler = new XorCsrfTokenRequestAttributeHandler();
		DeferredCsrfToken deferredCsrfToken = repository.loadDeferredToken(request, this.response);
		handler.handle(request, this.response, deferredCsrfToken);
		CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
		request.setParameter(token.getParameterName(), token.getToken());
		request.getSession().setAttribute("attribute1", "value1");
		loadConfig(SessionManagementDefaultSessionFixationServlet31Config.class);
		this.springSecurityFilterChain.doFilter(request, this.response, this.chain);
		assertThat(request.getSession().getId()).isNotEqualTo(id);
		assertThat(request.getSession().getAttribute("attribute1")).isEqualTo("value1");
	}

	private void loadConfig(Class<?>... classes) {
		AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
		context.register(classes);
		context.refresh();
		this.context = context;
		this.springSecurityFilterChain = this.context.getBean("springSecurityFilterChain", Filter.class);
	}

	@Configuration
	@EnableWebSecurity
	static class SessionManagementDefaultSessionFixationServlet31Config {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.formLogin(withDefaults())
				.sessionManagement(withDefaults());
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(PasswordEncodedUser.user());
		}

	}

}
