

/*
 * Copyright 2002-2013 the original author or authors.
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
package org.springframework.security.config.annotation.web.configurers

import org.springframework.context.annotation.Configuration
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.builders.WebSecurity
import org.springframework.security.config.annotation.web.configuration.BaseWebConfig
import org.springframework.security.web.FilterChainProxy
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource

/**
 * Tests to verify that all the functionality of <anonymous> attributes is present
 *
 * @author Rob Winch
 *
 */
public class NamespaceHttpFormLoginTests extends BaseSpringSpec {
	FilterChainProxy springSecurityFilterChain

	def "http/form-login"() {
		setup:
		loadConfig(FormLoginConfig)
			springSecurityFilterChain = context.getBean(FilterChainProxy)
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			response.getRedirectedUrl() == "http://localhost/login"
		when: "fail to log in"
			super.setup()
			request.servletPath = "/login"
			request.method = "POST"
			springSecurityFilterChain.doFilter(request,response,chain)
		then: "sent to login error page"
			response.getRedirectedUrl() == "/login?error"
		when: "login success"
			super.setup()
			request.servletPath = "/login"
			request.method = "POST"
			request.parameters.username = ["user"] as String[]
			request.parameters.password = ["password"] as String[]
			springSecurityFilterChain.doFilter(request,response,chain)
		then: "sent to default succes page"
			response.getRedirectedUrl() == "/"
	}

	@Configuration
	static class FormLoginConfig extends BaseWebConfig {

		@Override
		public void configure(WebSecurity web) throws Exception {
			web
				.ignoring()
					.antMatchers("/resources/**");
		}

		@Override
		protected void configure(HttpSecurity http) {
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.formLogin()
		}
	}

	def "http/form-login custom"() {
		setup:
			loadConfig(FormLoginCustomConfig)
			springSecurityFilterChain = context.getBean(FilterChainProxy)
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			response.getRedirectedUrl() == "http://localhost/authentication/login"
		when: "fail to log in"
			super.setup()
			request.servletPath = "/authentication/login/process"
			request.method = "POST"
			springSecurityFilterChain.doFilter(request,response,chain)
			then: "sent to login error page"
			response.getRedirectedUrl() == "/authentication/login?failed"
		when: "login success"
			super.setup()
			request.servletPath = "/authentication/login/process"
			request.method = "POST"
			request.parameters.username = ["user"] as String[]
			request.parameters.password = ["password"] as String[]
			springSecurityFilterChain.doFilter(request,response,chain)
		then: "sent to default succes page"
			response.getRedirectedUrl() == "/default"
	}

	@Configuration
	static class FormLoginCustomConfig extends BaseWebConfig {
		protected void configure(HttpSecurity http) throws Exception {
			boolean alwaysUseDefaultSuccess = true;
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.formLogin()
					.usernameParameter("username") // form-login@username-parameter
					.passwordParameter("password") // form-login@password-parameter
					.loginPage("/authentication/login") // form-login@login-page
					.failureUrl("/authentication/login?failed") // form-login@authentication-failure-url
					.loginProcessingUrl("/authentication/login/process") // form-login@login-processing-url
					.defaultSuccessUrl("/default", alwaysUseDefaultSuccess) // form-login@default-target-url / form-login@always-use-default-target
		}
	}

	def "http/form-login custom refs"() {
		when:
			loadConfig(FormLoginCustomRefsConfig)
			springSecurityFilterChain = context.getBean(FilterChainProxy)
			then: "CustomWebAuthenticationDetailsSource is used"
			findFilter(UsernamePasswordAuthenticationFilter).authenticationDetailsSource.class == CustomWebAuthenticationDetailsSource
		when: "fail to log in"
			request.servletPath = "/login"
			request.method = "POST"
			springSecurityFilterChain.doFilter(request,response,chain)
		then: "sent to login error page"
			response.getRedirectedUrl() == "/custom/failure"
		when: "login success"
			super.setup()
			request.servletPath = "/login"
			request.method = "POST"
			request.parameters.username = ["user"] as String[]
			request.parameters.password = ["password"] as String[]
			springSecurityFilterChain.doFilter(request,response,chain)
		then: "sent to default succes page"
			response.getRedirectedUrl() == "/custom/targetUrl"
	}

	@Configuration
	static class FormLoginCustomRefsConfig extends BaseWebConfig {
		protected void configure(HttpSecurity http) throws Exception {
			http
				.formLogin()
					.loginPage("/login")
					.failureHandler(new SimpleUrlAuthenticationFailureHandler("/custom/failure")) // form-login@authentication-failure-handler-ref
					.successHandler(new SavedRequestAwareAuthenticationSuccessHandler( defaultTargetUrl : "/custom/targetUrl" )) // form-login@authentication-success-handler-ref
					.authenticationDetailsSource(new CustomWebAuthenticationDetailsSource()) // form-login@authentication-details-source-ref
					.and();
		}
	}

	static class CustomWebAuthenticationDetailsSource extends WebAuthenticationDetailsSource {}
}
