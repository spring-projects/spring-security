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

import javax.servlet.http.HttpServletResponse

import spock.lang.Unroll

import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.web.access.AccessDeniedHandler
import org.springframework.security.web.csrf.CsrfFilter
import org.springframework.security.web.csrf.CsrfTokenRepository
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.security.web.util.matcher.RequestMatcher
import org.springframework.web.servlet.support.RequestDataValueProcessor

/**
 *
 * @author Rob Winch
 */
class CsrfConfigurerTests extends BaseSpringSpec {

	@Unroll
	def "csrf applied by default"() {
		setup:
		loadConfig(CsrfAppliedDefaultConfig)
		request.method = httpMethod
		clearCsrfToken()
		when:
		springSecurityFilterChain.doFilter(request,response,chain)
		then:
		response.status == httpStatus
		where:
		httpMethod | httpStatus
		'POST'     | HttpServletResponse.SC_FORBIDDEN
		'PUT'      | HttpServletResponse.SC_FORBIDDEN
		'PATCH'    | HttpServletResponse.SC_FORBIDDEN
		'DELETE'   | HttpServletResponse.SC_FORBIDDEN
		'INVALID'  | HttpServletResponse.SC_FORBIDDEN
		'GET'      | HttpServletResponse.SC_OK
		'HEAD'     | HttpServletResponse.SC_OK
		'TRACE'    | HttpServletResponse.SC_OK
		'OPTIONS'  | HttpServletResponse.SC_OK
	}

	def "csrf default creates CsrfRequestDataValueProcessor"() {
		when:
		loadConfig(CsrfAppliedDefaultConfig)
		then:
		context.getBean(RequestDataValueProcessor)
	}

	@EnableWebSecurity
	static class CsrfAppliedDefaultConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
		}
	}

	def "csrf disable"() {
		setup:
		loadConfig(DisableCsrfConfig)
		request.method = "POST"
		clearCsrfToken()
		when:
		springSecurityFilterChain.doFilter(request,response,chain)
		then:
		!findFilter(CsrfFilter)
		response.status == HttpServletResponse.SC_OK
	}

	@EnableWebSecurity
	static class DisableCsrfConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.csrf().disable()
		}
	}

	def "SEC-2498: Disable CSRF enables RequestCache for any method"() {
		setup:
		loadConfig(DisableCsrfEnablesRequestCacheConfig)
		request.requestURI = '/tosave'
		request.method = "POST"
		clearCsrfToken()
		when:
		springSecurityFilterChain.doFilter(request,response,chain)
		then:
		response.redirectedUrl
		when:
		super.setupWeb(request.session)
		request.method = "POST"
		request.servletPath = '/login'
		request.parameters['username'] = ['user'] as String[]
		request.parameters['password'] = ['password'] as String[]
		springSecurityFilterChain.doFilter(request,response,chain)
		then:
		response.redirectedUrl == 'http://localhost/tosave'
	}

	@EnableWebSecurity
	static class DisableCsrfEnablesRequestCacheConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.authorizeRequests()
					.anyRequest().authenticated()
					.and()
					.formLogin().and()
					.csrf().disable()
		}
		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
					.inMemoryAuthentication()
					.withUser("user").password("password").roles("USER")
		}
	}

	def "SEC-2422: csrf expire CSRF token and session-management invalid-session-url"() {
		setup:
		loadConfig(InvalidSessionUrlConfig)
		request.session.clearAttributes()
		request.setParameter("_csrf","abc")
		request.method = "POST"
		when: "No existing expected CsrfToken (session times out) and a POST"
		springSecurityFilterChain.doFilter(request,response,chain)
		then: "sent to the session timeout page page"
		response.status == HttpServletResponse.SC_MOVED_TEMPORARILY
		response.redirectedUrl == "/error/sessionError"
		when: "Existing expected CsrfToken and a POST (invalid token provided)"
		response = new MockHttpServletResponse()
		request = new MockHttpServletRequest(session: request.session, method:'POST')
		springSecurityFilterChain.doFilter(request,response,chain)
		then: "Access Denied occurs"
		response.status == HttpServletResponse.SC_FORBIDDEN
	}

	@EnableWebSecurity
	static class InvalidSessionUrlConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.csrf().and()
					.sessionManagement()
					.invalidSessionUrl("/error/sessionError")
		}
	}

	def "csrf requireCsrfProtectionMatcher"() {
		setup:
		RequireCsrfProtectionMatcherConfig.matcher = Mock(RequestMatcher)
		RequireCsrfProtectionMatcherConfig.matcher.matches(_) >>> [false, true]
		loadConfig(RequireCsrfProtectionMatcherConfig)
		clearCsrfToken()
		when:
		springSecurityFilterChain.doFilter(request,response,chain)
		then:
		response.status == HttpServletResponse.SC_OK
		when:
		springSecurityFilterChain.doFilter(request,response,chain)
		then:
		response.status == HttpServletResponse.SC_FORBIDDEN
	}

	@EnableWebSecurity
	static class RequireCsrfProtectionMatcherConfig extends WebSecurityConfigurerAdapter {
		static RequestMatcher matcher

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.csrf()
					.requireCsrfProtectionMatcher(matcher)
		}
	}

	def "csrf csrfTokenRepository"() {
		setup:
		CsrfTokenRepositoryConfig.repo = Mock(CsrfTokenRepository)
		loadConfig(CsrfTokenRepositoryConfig)
		clearCsrfToken()
		when:
		springSecurityFilterChain.doFilter(request,response,chain)
		then:
		1 * CsrfTokenRepositoryConfig.repo.loadToken(_) >> csrfToken
		response.status == HttpServletResponse.SC_OK
	}

	def "csrf clears on logout"() {
		setup:
		CsrfTokenRepositoryConfig.repo = Mock(CsrfTokenRepository)
		1 * CsrfTokenRepositoryConfig.repo.loadToken(_) >> csrfToken
		loadConfig(CsrfTokenRepositoryConfig)
		login()
		request.method = "POST"
		request.servletPath = "/logout"
		when:
		springSecurityFilterChain.doFilter(request,response,chain)
		then:
		1 *  CsrfTokenRepositoryConfig.repo.saveToken(null, _, _)
	}

	def "csrf clears on login"() {
		setup:
		CsrfTokenRepositoryConfig.repo = Mock(CsrfTokenRepository)
		(1.._) * CsrfTokenRepositoryConfig.repo.loadToken(_) >> csrfToken
		(1.._) * CsrfTokenRepositoryConfig.repo.generateToken(_) >> csrfToken
		loadConfig(CsrfTokenRepositoryConfig)
		request.method = "POST"
		request.getSession()
		request.servletPath = "/login"
		request.setParameter("username", "user")
		request.setParameter("password", "password")
		when:
		springSecurityFilterChain.doFilter(request,response,chain)
		then:
		response.redirectedUrl == "/"
		(1.._) *  CsrfTokenRepositoryConfig.repo.saveToken(null, _, _)
	}

	@EnableWebSecurity
	static class CsrfTokenRepositoryConfig extends WebSecurityConfigurerAdapter {
		static CsrfTokenRepository repo

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.formLogin()
					.and()
					.csrf()
					.csrfTokenRepository(repo)
		}
		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
					.inMemoryAuthentication()
					.withUser("user").password("password").roles("USER")
		}
	}

	def "csrf access denied handler"() {
		setup:
		AccessDeniedHandlerConfig.deniedHandler = Mock(AccessDeniedHandler)
		1 * AccessDeniedHandlerConfig.deniedHandler.handle(_, _, _)
		loadConfig(AccessDeniedHandlerConfig)
		clearCsrfToken()
		request.method = "POST"
		when:
		springSecurityFilterChain.doFilter(request,response,chain)
		then:
		response.status == HttpServletResponse.SC_OK
	}

	@EnableWebSecurity
	static class AccessDeniedHandlerConfig extends WebSecurityConfigurerAdapter {
		static AccessDeniedHandler deniedHandler

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.exceptionHandling()
					.accessDeniedHandler(deniedHandler)
		}
	}

	def "formLogin requires CSRF token"() {
		setup:
		loadConfig(FormLoginConfig)
		clearCsrfToken()
		request.setParameter("username", "user")
		request.setParameter("password", "password")
		request.servletPath = "/login"
		request.method = "POST"
		when:
		springSecurityFilterChain.doFilter(request,response,chain)
		then:
		response.status == HttpServletResponse.SC_FORBIDDEN
		currentAuthentication == null
	}

	@EnableWebSecurity
	static class FormLoginConfig extends WebSecurityConfigurerAdapter {
		static AccessDeniedHandler deniedHandler

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.formLogin()
		}
	}

	def "logout requires CSRF token"() {
		setup:
		loadConfig(LogoutConfig)
		clearCsrfToken()
		login()
		request.servletPath = "/logout"
		request.method = "POST"
		when:
		springSecurityFilterChain.doFilter(request,response,chain)
		then: "logout is not allowed and user is still authenticated"
		response.status == HttpServletResponse.SC_FORBIDDEN
		currentAuthentication != null
	}

	def "SEC-2543: CSRF means logout requires POST"() {
		setup:
		loadConfig(LogoutConfig)
		login()
		request.servletPath = "/logout"
		request.method = "GET"
		when:
		springSecurityFilterChain.doFilter(request,response,chain)
		then: "logout with GET is not performed"
		currentAuthentication != null
	}

	@EnableWebSecurity
	static class LogoutConfig extends WebSecurityConfigurerAdapter {
		static AccessDeniedHandler deniedHandler

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.formLogin()
		}
	}

	def "CSRF can explicitly enable GET for logout"() {
		setup:
		loadConfig(LogoutAllowsGetConfig)
		login()
		request.servletPath = "/logout"
		request.method = "GET"
		when:
		springSecurityFilterChain.doFilter(request,response,chain)
		then: "logout with GET is not performed"
		currentAuthentication == null
	}

	@EnableWebSecurity
	static class LogoutAllowsGetConfig extends WebSecurityConfigurerAdapter {
		static AccessDeniedHandler deniedHandler

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.formLogin().and()
					.logout()
					.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
		}
	}

	def "csrf disables POST requests from RequestCache"() {
		setup:
		CsrfDisablesPostRequestFromRequestCacheConfig.repo = Mock(CsrfTokenRepository)
		(1.._) * CsrfDisablesPostRequestFromRequestCacheConfig.repo.generateToken(_) >> csrfToken
		loadConfig(CsrfDisablesPostRequestFromRequestCacheConfig)
		request.servletPath = "/some-url"
		request.requestURI = "/some-url"
		request.method = "POST"
		when: "CSRF passes and our session times out"
		springSecurityFilterChain.doFilter(request,response,chain)
		then: "sent to the login page"
		(1.._) * CsrfDisablesPostRequestFromRequestCacheConfig.repo.loadToken(_) >> csrfToken
		response.status == HttpServletResponse.SC_MOVED_TEMPORARILY
		response.redirectedUrl == "http://localhost/login"
		when: "authenticate successfully"
		super.setupWeb(request.session)
		request.servletPath = "/login"
		request.setParameter("username","user")
		request.setParameter("password","password")
		request.method = "POST"
		springSecurityFilterChain.doFilter(request,response,chain)
		then: "sent to default success because we don't want csrf attempts made prior to authentication to pass"
		(1.._) * CsrfDisablesPostRequestFromRequestCacheConfig.repo.loadToken(_) >> csrfToken
		response.status == HttpServletResponse.SC_MOVED_TEMPORARILY
		response.redirectedUrl == "/"
	}

	def "csrf enables GET requests with RequestCache"() {
		setup:
		CsrfDisablesPostRequestFromRequestCacheConfig.repo = Mock(CsrfTokenRepository)
		(1.._) * CsrfDisablesPostRequestFromRequestCacheConfig.repo.generateToken(_) >> csrfToken
		loadConfig(CsrfDisablesPostRequestFromRequestCacheConfig)
		request.servletPath = "/some-url"
		request.requestURI = "/some-url"
		request.method = "GET"
		when: "CSRF passes and our session times out"
		springSecurityFilterChain.doFilter(request,response,chain)
		then: "sent to the login page"
		(1.._) * CsrfDisablesPostRequestFromRequestCacheConfig.repo.loadToken(_) >> csrfToken
		response.status == HttpServletResponse.SC_MOVED_TEMPORARILY
		response.redirectedUrl == "http://localhost/login"
		when: "authenticate successfully"
		super.setupWeb(request.session)
		request.servletPath = "/login"
		request.setParameter("username","user")
		request.setParameter("password","password")
		request.method = "POST"
		springSecurityFilterChain.doFilter(request,response,chain)
		then: "sent to original URL since it was a GET"
		(1.._) * CsrfDisablesPostRequestFromRequestCacheConfig.repo.loadToken(_) >> csrfToken
		response.status == HttpServletResponse.SC_MOVED_TEMPORARILY
		response.redirectedUrl == "http://localhost/some-url"
	}

	@EnableWebSecurity
	static class CsrfDisablesPostRequestFromRequestCacheConfig extends WebSecurityConfigurerAdapter {
		static CsrfTokenRepository repo

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.authorizeRequests()
					.anyRequest().authenticated()
					.and()
					.formLogin()
					.and()
					.csrf()
					.csrfTokenRepository(repo)
		}
		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
					.inMemoryAuthentication()
					.withUser("user").password("password").roles("USER")
		}
	}

	def 'SEC-2749: requireCsrfProtectionMatcher null'() {
		when:
		new CsrfConfigurer<>().requireCsrfProtectionMatcher(null)
		then:
		thrown(IllegalArgumentException)
	}

	def 'default does not create session'() {
		setup:
		request = new MockHttpServletRequest(method:'GET')
		loadConfig(DefaultDoesNotCreateSession)
		when:
		springSecurityFilterChain.doFilter(request,response,chain)
		then:
		request.getSession(false) == null
	}

	@EnableWebSecurity(debug=true)
	static class DefaultDoesNotCreateSession extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.authorizeRequests()
					.anyRequest().permitAll()
					.and()
					.formLogin().and()
					.httpBasic();
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
					.inMemoryAuthentication()
					.withUser("user").password("password").roles("USER")
		}
	}

	def clearCsrfToken() {
		request.removeAllParameters()
	}
}
