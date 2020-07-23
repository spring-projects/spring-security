/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.config.annotation.web;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;

import javax.servlet.http.HttpServletResponse;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Demonstrate the samples.
 *
 * @author Rob Winch
 * @author Joe Grandja
 */
public class SampleWebSecurityConfigurerAdapterTests {
	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private FilterChainProxy springSecurityFilterChain;

	private MockHttpServletRequest request;
	private MockHttpServletResponse response;
	private MockFilterChain chain;

	@Before
	public void setup() {
		this.request = new MockHttpServletRequest("GET", "");
		this.response = new MockHttpServletResponse();
		this.chain = new MockFilterChain();

		CsrfToken csrfToken = new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "CSRF-TOKEN-TEST");
		new HttpSessionCsrfTokenRepository().saveToken(csrfToken, this.request, this.response);
		this.request.setParameter(csrfToken.getParameterName(), csrfToken.getToken());
	}

	@Test
	public void helloWorldSampleWhenRequestSecureResourceThenRedirectToLogin() throws Exception {
		this.spring.register(HelloWorldWebSecurityConfigurerAdapter.class).autowire();

		this.request.addHeader("Accept", "text/html");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getRedirectedUrl()).isEqualTo("http://localhost/login");
	}

	@Test
	public void helloWorldSampleWhenRequestLoginWithoutCredentialsThenRedirectToLogin() throws Exception {
		this.spring.register(HelloWorldWebSecurityConfigurerAdapter.class).autowire();

		this.request.setServletPath("/login");
		this.request.setMethod("POST");
		this.request.addHeader("Accept", "text/html");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getRedirectedUrl()).isEqualTo("/login?error");
	}

	@Test
	public void helloWorldSampleWhenRequestLoginWithValidCredentialsThenRedirectToIndex() throws Exception {
		this.spring.register(HelloWorldWebSecurityConfigurerAdapter.class).autowire();

		this.request.setServletPath("/login");
		this.request.setMethod("POST");
		this.request.addHeader("Accept", "text/html");
		this.request.addParameter("username", "user");
		this.request.addParameter("password", "password");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getRedirectedUrl()).isEqualTo("/");
	}

	/**
	 * <code>
	 *   <http>
	 *     <intercept-url pattern="/resources/**" access="permitAll"/>
	 *     <intercept-url pattern="/**" access="authenticated"/>
	 *     <logout
	 *         logout-success-url="/login?logout"
	 *         logout-url="/logout"
	 *     <form-login
	 *         authentication-failure-url="/login?error"
	 *         login-page="/login" <!-- Except Spring Security renders the login page -->
	 *         login-processing-url="/login" <!-- but only POST -->
	 *         password-parameter="password"
	 *         username-parameter="username"
	 *     />
	 *   </http>
	 *   <authentication-manager>
	 *     <authentication-provider>
	 *       <user-service>
	 *         <user username="user" password="password" authorities="ROLE_USER"/>
	 *       </user-service>
	 *     </authentication-provider>
	 *   </authentication-manager>
	 * </code>
	 * @author Rob Winch
	 */
	@EnableWebSecurity
	public static class HelloWorldWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user());
		}
	}


	@Test
	public void readmeSampleWhenRequestSecureResourceThenRedirectToLogin() throws Exception {
		this.spring.register(SampleWebSecurityConfigurerAdapter.class).autowire();

		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getRedirectedUrl()).isEqualTo("http://localhost/login");
	}

	@Test
	public void readmeSampleWhenRequestLoginWithoutCredentialsThenRedirectToLogin() throws Exception {
		this.spring.register(SampleWebSecurityConfigurerAdapter.class).autowire();

		this.request.setServletPath("/login");
		this.request.setMethod("POST");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getRedirectedUrl()).isEqualTo("/login?error");
	}

	@Test
	public void readmeSampleWhenRequestLoginWithValidCredentialsThenRedirectToIndex() throws Exception {
		this.spring.register(SampleWebSecurityConfigurerAdapter.class).autowire();

		this.request.setServletPath("/login");
		this.request.setMethod("POST");
		this.request.addParameter("username", "user");
		this.request.addParameter("password", "password");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getRedirectedUrl()).isEqualTo("/");
	}

	/**
	 * <code>
	 *   <http security="none" pattern="/resources/**"/>
	 *   <http>
	 *     <intercept-url pattern="/logout" access="permitAll"/>
	 *     <intercept-url pattern="/login" access="permitAll"/>
	 *     <intercept-url pattern="/signup" access="permitAll"/>
	 *     <intercept-url pattern="/about" access="permitAll"/>
	 *     <intercept-url pattern="/**" access="hasRole('ROLE_USER')"/>
	 *     <logout
	 *         logout-success-url="/login?logout"
	 *         logout-url="/logout"
	 *     <form-login
	 *         authentication-failure-url="/login?error"
	 *         login-page="/login"
	 *         login-processing-url="/login" <!-- but only POST -->
	 *         password-parameter="password"
	 *         username-parameter="username"
	 *     />
	 *   </http>
	 *   <authentication-manager>
	 *     <authentication-provider>
	 *       <user-service>
	 *         <user username="user" password="password" authorities="ROLE_USER"/>
	 *         <user username="admin" password="password" authorities="ROLE_USER,ROLE_ADMIN"/>
	 *       </user-service>
	 *     </authentication-provider>
	 *   </authentication-manager>
	 * </code>
	 * @author Rob Winch
	 */
	@EnableWebSecurity
	public static class SampleWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

		@Override
		public void configure(WebSecurity web) {
			web
				.ignoring()
					.antMatchers("/resources/**");
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.antMatchers("/signup", "/about").permitAll()
					.anyRequest().hasRole("USER")
					.and()
				.formLogin()
					.loginPage("/login")
						// set permitAll for all URLs associated with Form Login
						.permitAll();
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user())
					.withUser(PasswordEncodedUser.admin());
		}
	}


	@Test
	public void multiHttpSampleWhenRequestSecureResourceThenRedirectToLogin() throws Exception {
		this.spring.register(SampleMultiHttpSecurityConfig.class).autowire();

		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getRedirectedUrl()).isEqualTo("http://localhost/login");
	}

	@Test
	public void multiHttpSampleWhenRequestLoginWithoutCredentialsThenRedirectToLogin() throws Exception {
		this.spring.register(SampleMultiHttpSecurityConfig.class).autowire();

		this.request.setServletPath("/login");
		this.request.setMethod("POST");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getRedirectedUrl()).isEqualTo("/login?error");
	}

	@Test
	public void multiHttpSampleWhenRequestLoginWithValidCredentialsThenRedirectToIndex() throws Exception {
		this.spring.register(SampleMultiHttpSecurityConfig.class).autowire();

		this.request.setServletPath("/login");
		this.request.setMethod("POST");
		this.request.addParameter("username", "user");
		this.request.addParameter("password", "password");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getRedirectedUrl()).isEqualTo("/");
	}

	@Test
	public void multiHttpSampleWhenRequestProtectedResourceThenStatusUnauthorized() throws Exception {
		this.spring.register(SampleMultiHttpSecurityConfig.class).autowire();

		this.request.setServletPath("/api/admin/test");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
	}

	@Test
	public void multiHttpSampleWhenRequestAdminResourceWithRegularUserThenStatusForbidden() throws Exception {
		this.spring.register(SampleMultiHttpSecurityConfig.class).autowire();

		this.request.setServletPath("/api/admin/test");
		this.request.addHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString("user:password".getBytes()));
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
	}

	@Test
	public void multiHttpSampleWhenRequestAdminResourceWithAdminUserThenStatusOk() throws Exception {
		this.spring.register(SampleMultiHttpSecurityConfig.class).autowire();

		this.request.setServletPath("/api/admin/test");
		this.request.addHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString("admin:password".getBytes()));
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
	}

	/**
	 * <code>
	 *   <http security="none" pattern="/resources/**"/>
	 *   <http pattern="/api/**">
	 *     <intercept-url pattern="/api/admin/**" access="hasRole('ROLE_ADMIN')"/>
	 *     <intercept-url pattern="/api/**" access="hasRole('ROLE_USER')"/>
	 *     <http-basic />
	 *   </http>
	 *   <http>
	 *     <intercept-url pattern="/logout" access="permitAll"/>
	 *     <intercept-url pattern="/login" access="permitAll"/>
	 *     <intercept-url pattern="/signup" access="permitAll"/>
	 *     <intercept-url pattern="/about" access="permitAll"/>
	 *     <intercept-url pattern="/**" access="hasRole('ROLE_USER')"/>
	 *     <logout
	 *         logout-success-url="/login?logout"
	 *         logout-url="/logout"
	 *     <form-login
	 *         authentication-failure-url="/login?error"
	 *         login-page="/login"
	 *         login-processing-url="/login" <!-- but only POST -->
	 *         password-parameter="password"
	 *         username-parameter="username"
	 *     />
	 *   </http>
	 *   <authentication-manager>
	 *     <authentication-provider>
	 *       <user-service>
	 *         <user username="user" password="password" authorities="ROLE_USER"/>
	 *         <user username="admin" password="password" authorities="ROLE_USER,ROLE_ADMIN"/>
	 *       </user-service>
	 *     </authentication-provider>
	 *   </authentication-manager>
	 * </code>
	 * @author Rob Winch
	 */
	@EnableWebSecurity
	public static class SampleMultiHttpSecurityConfig {
		@Autowired
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user())
					.withUser(PasswordEncodedUser.admin());
		}

		@Configuration
		@Order(1)
		public static class ApiWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {
			protected void configure(HttpSecurity http) throws Exception {
				// @formatter:off
				http
					.antMatcher("/api/**")
						.authorizeRequests()
							.antMatchers("/api/admin/**").hasRole("ADMIN")
							.antMatchers("/api/**").hasRole("USER")
							.and()
						.httpBasic();
				// @formatter:on
			}
		}

		@Configuration
		public static class FormLoginWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {
			@Override
			public void configure(WebSecurity web) {
				web
					.ignoring()
						.antMatchers("/resources/**");
			}

			@Override
			protected void configure(HttpSecurity http) throws Exception {
				// @formatter:off
				http
					.authorizeRequests()
						.antMatchers("/signup", "/about").permitAll()
						.anyRequest().hasRole("USER")
						.and()
					.formLogin()
						.loginPage("/login")
							.permitAll();
				// @formatter:on
			}
		}
	}
}
