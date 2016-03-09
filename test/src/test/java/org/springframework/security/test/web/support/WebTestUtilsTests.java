/*
 * Copyright 2002-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.test.web.support;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.support.WebTestUtils.getCsrfTokenRepository;
import static org.springframework.security.test.web.support.WebTestUtils.getSecurityContextRepository;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

@RunWith(MockitoJUnitRunner.class)
public class WebTestUtilsTests {
	@Mock
	private SecurityContextRepository contextRepo;
	@Mock
	private CsrfTokenRepository csrfRepo;

	private MockHttpServletRequest request;
	private ConfigurableApplicationContext context;

	@Before
	public void setup() {
		request = new MockHttpServletRequest();
	}

	@After
	public void cleanup() {
		if (context != null) {
			context.close();
		}
	}

	@Test
	public void getCsrfTokenRepositorytNoWac() {
		assertThat(getCsrfTokenRepository(request)).isInstanceOf(
				HttpSessionCsrfTokenRepository.class);
	}

	@Test
	public void getCsrfTokenRepositorytNoSecurity() {
		loadConfig(Config.class);
		assertThat(getCsrfTokenRepository(request)).isInstanceOf(
				HttpSessionCsrfTokenRepository.class);
	}

	@Test
	public void getCsrfTokenRepositorytSecurityNoCsrf() {
		loadConfig(SecurityNoCsrfConfig.class);
		assertThat(getCsrfTokenRepository(request)).isInstanceOf(
				HttpSessionCsrfTokenRepository.class);
	}

	@Test
	public void getCsrfTokenRepositorytSecurityCustomRepo() {
		CustomSecurityConfig.CONTEXT_REPO = contextRepo;
		CustomSecurityConfig.CSRF_REPO = csrfRepo;
		loadConfig(CustomSecurityConfig.class);
		assertThat(getCsrfTokenRepository(request)).isSameAs(csrfRepo);
	}

	// getSecurityContextRepository

	@Test
	public void getSecurityContextRepositoryNoWac() {
		assertThat(getSecurityContextRepository(request)).isInstanceOf(
				HttpSessionSecurityContextRepository.class);
	}

	@Test
	public void getSecurityContextRepositoryNoSecurity() {
		loadConfig(Config.class);
		assertThat(getSecurityContextRepository(request)).isInstanceOf(
				HttpSessionSecurityContextRepository.class);
	}

	@Test
	public void getSecurityContextRepositorySecurityNoCsrf() {
		loadConfig(SecurityNoCsrfConfig.class);
		assertThat(getSecurityContextRepository(request)).isInstanceOf(
				HttpSessionSecurityContextRepository.class);
	}

	@Test
	public void getSecurityContextRepositorySecurityCustomRepo() {
		CustomSecurityConfig.CONTEXT_REPO = contextRepo;
		CustomSecurityConfig.CSRF_REPO = csrfRepo;
		loadConfig(CustomSecurityConfig.class);
		assertThat(getSecurityContextRepository(request)).isSameAs(contextRepo);
	}

	// gh-3343
	@Test
	public void findFilterNoMatchingFilters() {
		loadConfig(PartialSecurityConfig.class);

		assertThat(WebTestUtils.findFilter(request, SecurityContextPersistenceFilter.class)).isNull();
	}

	private void loadConfig(Class<?> config) {
		AnnotationConfigWebApplicationContext context = new AnnotationConfigWebApplicationContext();
		context.register(config);
		context.refresh();
		this.context = context;
		request.getServletContext().setAttribute(
				WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE, context);
	}

	@Configuration
	static class Config {
	}

	@EnableWebSecurity
	static class SecurityNoCsrfConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.csrf().disable();
		}
	}

	@EnableWebSecurity
	static class CustomSecurityConfig extends WebSecurityConfigurerAdapter {
		static CsrfTokenRepository CSRF_REPO;
		static SecurityContextRepository CONTEXT_REPO;

		// @formatter:off
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.csrf()
					.csrfTokenRepository(CSRF_REPO)
					.and()
				.securityContext()
					.securityContextRepository(CONTEXT_REPO);
		}
		// @formatter:on
	}



	@EnableWebSecurity
	static class PartialSecurityConfig extends WebSecurityConfigurerAdapter {

		// @formatter:off
		@Override
		public void configure(HttpSecurity http) throws Exception {
			http
				.antMatcher("/willnotmatchthis");
		}
		// @formatter:on
	}
}