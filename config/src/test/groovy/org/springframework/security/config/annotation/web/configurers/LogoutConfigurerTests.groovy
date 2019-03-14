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

import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.config.annotation.AnyObjectPostProcessor
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.web.authentication.RememberMeServices
import org.springframework.security.web.authentication.logout.LogoutFilter
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler
import org.springframework.security.web.util.matcher.RequestMatcher

/**
 *
 * @author Rob Winch
 */
class LogoutConfigurerTests extends BaseSpringSpec {

	def defaultLogoutSuccessHandlerForNullLogoutHandler() {
		setup:
		LogoutConfigurer config = new LogoutConfigurer();
		when:
		config.defaultLogoutSuccessHandlerFor(null, Mock(RequestMatcher))
		then:
		thrown(IllegalArgumentException)
	}

	def defaultLogoutSuccessHandlerForNullMatcher() {
		setup:
		LogoutConfigurer config = new LogoutConfigurer();
		when:
		config.defaultLogoutSuccessHandlerFor(Mock(LogoutSuccessHandler), null)
		then:
		thrown(IllegalArgumentException)
	}

	def "logout ObjectPostProcessor"() {
		setup:
			AnyObjectPostProcessor opp = Mock()
			HttpSecurity http = new HttpSecurity(opp, authenticationBldr, [:])
		when:
			http
				.logout()
					.and()
				.build()

		then: "LogoutFilter is registered with LifecycleManager"
			1 * opp.postProcess(_ as LogoutFilter) >> {LogoutFilter o -> o}
	}

	def "invoke logout twice does not override"() {
		when:
			loadConfig(InvokeTwiceDoesNotOverride)
			request.method = "POST"
			request.servletPath = "/custom/logout"
			findFilter(LogoutFilter).doFilter(request,response,chain)
		then:
			response.redirectedUrl == "/login?logout"
	}

	@EnableWebSecurity
	static class InvokeTwiceDoesNotOverride extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.logout()
					.logoutUrl("/custom/logout")
					.and()
				.logout()
		}
	}

	def "Logout allows other methods if CSRF is disabled"() {
		when:
			loadConfig(CsrfDisabledConfig)
			request.method = method
			request.servletPath = "/logout"
			findFilter(LogoutFilter).doFilter(request,response,chain)
		then:
			response.status == httpStatus.value()
			response.redirectedUrl == url
		where:
			method    | httpStatus       | url
			"GET"     | HttpStatus.FOUND | "/login?logout"
			"POST"    | HttpStatus.FOUND | "/login?logout"
			"PUT"     | HttpStatus.FOUND | "/login?logout"
			"DELETE"  | HttpStatus.FOUND | "/login?logout"
			"OPTIONS" | HttpStatus.OK    | null
			"HEAD"    | HttpStatus.OK    | null
			"TRACE"   | HttpStatus.OK    | null

	}

	@EnableWebSecurity
	static class CsrfDisabledConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.csrf().disable()
				.logout()
		}
	}


	def "Logout allows other methods if CSRF is disabled with custom logout URL"() {
		when:
			loadConfig(CsrfDisabledCustomLogoutUrlConfig)
			request.method = method
			request.servletPath = "/custom/logout"
			findFilter(LogoutFilter).doFilter(request,response,chain)
		then:
			response.status == httpStatus.value()
			response.redirectedUrl == url
		where:
			method    | httpStatus       | url
			"GET"     | HttpStatus.FOUND | "/login?logout"
			"POST"    | HttpStatus.FOUND | "/login?logout"
			"PUT"     | HttpStatus.FOUND | "/login?logout"
			"DELETE"  | HttpStatus.FOUND | "/login?logout"
			"OPTIONS" | HttpStatus.OK    | null
			"HEAD"    | HttpStatus.OK    | null
			"TRACE"   | HttpStatus.OK    | null

	}

	@EnableWebSecurity
	static class CsrfDisabledCustomLogoutUrlConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.logout()
					.logoutUrl("/custom/logout")
					.and()
				.csrf().disable()
		}
	}

	def "SEC-3170: LogoutConfigurer RememberMeService not LogoutHandler"() {
		setup:
			RememberMeNoLogoutHandler.REMEMBER_ME = Mock(RememberMeServices)
			loadConfig(RememberMeNoLogoutHandler)
			request.method = "POST"
			request.servletPath = "/logout"
		when:
			findFilter(LogoutFilter).doFilter(request,response,chain)
		then:
			response.redirectedUrl == "/login?logout"
	}

	def "SEC-3170: LogoutConfigurer prevents null LogoutHandler"() {
		when:
			new LogoutConfigurer().addLogoutHandler(null)
		then:
			thrown(IllegalArgumentException)
	}

	@EnableWebSecurity
	static class RememberMeNoLogoutHandler extends WebSecurityConfigurerAdapter {
		static RememberMeServices REMEMBER_ME

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.rememberMe()
					.rememberMeServices(REMEMBER_ME)
		}
	}

	def "LogoutConfigurer content negotiation text/html redirects"() {
		setup:
			loadConfig(LogoutHandlerContentNegotiation)
		when:
			login()
			request.method = 'POST'
			request.servletPath = '/logout'
			request.addHeader('Accept', 'text/html')
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			response.status == 302
			response.redirectedUrl == '/login?logout'
	}

	// gh-3282
	def "LogoutConfigurer content negotiation json 201"() {
		setup:
			loadConfig(LogoutHandlerContentNegotiation)
		when:
			login()
			request.method = 'POST'
			request.servletPath = '/logout'
			request.addHeader('Accept', 'application/json')
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			response.status == 204
	}

	// gh-4831
	def "LogoutConfigurer content negotiation all 201"() {
		setup:
		loadConfig(LogoutHandlerContentNegotiation)
		when:
		login()
		request.method = 'POST'
		request.servletPath = '/logout'
		request.addHeader('Accept', MediaType.ALL_VALUE)
		springSecurityFilterChain.doFilter(request,response,chain)
		then:
		response.status == 204
	}

	@EnableWebSecurity
	static class LogoutHandlerContentNegotiation extends WebSecurityConfigurerAdapter {
	}
	// gh-3902
	def "logout in chrome is 302"() {
		setup:
		loadConfig(LogoutHandlerContentNegotiationForChrome)
		when:
		login()
		request.method = 'POST'
		request.servletPath = '/logout'
		request.addHeader('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8')
		springSecurityFilterChain.doFilter(request,response,chain)
		then:
		response.status == 302
	}

	@EnableWebSecurity
	static class LogoutHandlerContentNegotiationForChrome extends WebSecurityConfigurerAdapter {
	}

	// gh-3997
	def "LogoutConfigurer for XMLHttpRequest is 204"() {
		setup:
			loadConfig(LogoutXMLHttpRequestConfig)
		when:
			login()
			request.method = 'POST'
			request.servletPath = '/logout'
			request.addHeader('Accept', 'text/html,application/json')
			request.addHeader('X-Requested-With', 'XMLHttpRequest')
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			response.status == 204
	}

	@EnableWebSecurity
	static class LogoutXMLHttpRequestConfig extends WebSecurityConfigurerAdapter {
	}
}
