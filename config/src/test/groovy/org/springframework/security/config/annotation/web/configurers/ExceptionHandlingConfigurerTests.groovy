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

import org.springframework.security.core.userdetails.User
import org.springframework.security.provisioning.InMemoryUserDetailsManager

import javax.servlet.http.HttpServletResponse

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration
import org.springframework.http.MediaType
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.config.annotation.AnyObjectPostProcessor
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.annotation.web.configurers.JeeConfigurerTests.InvokeTwiceDoesNotOverride;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;

import spock.lang.Unroll

/**
 *
 * @author Rob Winch
 */
class ExceptionHandlingConfigurerTests extends BaseSpringSpec {

	def "exception ObjectPostProcessor"() {
		setup: "initialize the AUTH_FILTER as a mock"
			AnyObjectPostProcessor opp = Mock()
		when:
			HttpSecurity http = new HttpSecurity(opp, authenticationBldr, [:])
			http
				.exceptionHandling()
					.and()
				.build()

		then: "ExceptionTranslationFilter is registered with LifecycleManager"
			1 * opp.postProcess(_ as ExceptionTranslationFilter) >> {ExceptionTranslationFilter o -> o}
	}

	@Unroll
	def "SEC-2199: defaultEntryPoint for httpBasic and formLogin"(String acceptHeader, int httpStatus) {
		setup:
			loadConfig(HttpBasicAndFormLoginEntryPointsConfig)
		when:
			request.addHeader("Accept", acceptHeader)
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			response.status == httpStatus
		where:
			acceptHeader                                 | httpStatus
			MediaType.APPLICATION_XHTML_XML_VALUE        | HttpServletResponse.SC_MOVED_TEMPORARILY
			MediaType.IMAGE_GIF_VALUE                    | HttpServletResponse.SC_MOVED_TEMPORARILY
			MediaType.IMAGE_JPEG_VALUE                   | HttpServletResponse.SC_MOVED_TEMPORARILY
			MediaType.IMAGE_PNG_VALUE                    | HttpServletResponse.SC_MOVED_TEMPORARILY
			MediaType.TEXT_HTML_VALUE                    | HttpServletResponse.SC_MOVED_TEMPORARILY
			MediaType.TEXT_PLAIN_VALUE                   | HttpServletResponse.SC_MOVED_TEMPORARILY
			MediaType.APPLICATION_ATOM_XML_VALUE         | HttpServletResponse.SC_UNAUTHORIZED
			MediaType.APPLICATION_FORM_URLENCODED_VALUE  | HttpServletResponse.SC_UNAUTHORIZED
			MediaType.APPLICATION_JSON_VALUE             | HttpServletResponse.SC_UNAUTHORIZED
			MediaType.APPLICATION_OCTET_STREAM_VALUE     | HttpServletResponse.SC_UNAUTHORIZED
			MediaType.APPLICATION_XML_VALUE              | HttpServletResponse.SC_UNAUTHORIZED
			MediaType.MULTIPART_FORM_DATA_VALUE          | HttpServletResponse.SC_UNAUTHORIZED
			MediaType.TEXT_XML_VALUE                     | HttpServletResponse.SC_UNAUTHORIZED
	}

	// gh-4831
	def "Accept */* is Basic by default"() {
		setup:
		loadConfig(DefaultSecurityConfig)
		when:
		request.addHeader("Accept", MediaType.ALL_VALUE)
		springSecurityFilterChain.doFilter(request,response,chain)
		then:
		response.status == HttpServletResponse.SC_UNAUTHORIZED
	}

	def "Chrome is Form by default"() {
		setup:
		loadConfig(DefaultSecurityConfig)
		when:
		request.addHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8")
		springSecurityFilterChain.doFilter(request,response,chain)
		then:
		response.status == HttpServletResponse.SC_MOVED_TEMPORARILY
	}

	def "ContentNegotiationStrategy defaults to HeaderContentNegotiationStrategy"() {
		when:
			loadConfig(HttpBasicAndFormLoginEntryPointsConfig)
			DelegatingAuthenticationEntryPoint delegateEntryPoint = findFilter(ExceptionTranslationFilter).authenticationEntryPoint
		then:
			def entryPoints = delegateEntryPoint.entryPoints.keySet() as List
			entryPoints[0].requestMatchers[1].requestMatchers[1].contentNegotiationStrategy.class == HeaderContentNegotiationStrategy
			entryPoints[1].requestMatchers[1].contentNegotiationStrategy.class == HeaderContentNegotiationStrategy
	}

	def "401 for text/plain and X-Requested-With:XMLHttpRequest"() {
		setup:
			loadConfig(HttpBasicAndFormLoginEntryPointsConfig)
		when:
			request.addHeader("Accept", MediaType.TEXT_PLAIN_VALUE)
			request.addHeader("X-Requested-With", "XMLHttpRequest")
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			response.status == HttpServletResponse.SC_UNAUTHORIZED
	}

	@EnableWebSecurity
	static class DefaultSecurityConfig {

		@Bean
		public InMemoryUserDetailsManager userDetailsManager() {
			return new InMemoryUserDetailsManager(User.withDefaultPasswordEncoder()
				.username("user")
				.password("password")
				.roles("USER")
				.build()
			);
		}
	}

	@EnableWebSecurity
	static class HttpBasicAndFormLoginEntryPointsConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
				.inMemoryAuthentication()
					.withUser("user").password("password").roles("USER")
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.httpBasic()
					.and()
				.formLogin()
		}
	}

	def "ContentNegotiationStrategy overrides with @Bean"() {
		setup:
			OverrideContentNegotiationStrategySharedObjectConfig.CNS = Mock(ContentNegotiationStrategy)
		when:
			loadConfig(OverrideContentNegotiationStrategySharedObjectConfig)
			DelegatingAuthenticationEntryPoint delegateEntryPoint = findFilter(ExceptionTranslationFilter).authenticationEntryPoint
		then:
			def entryPoints = delegateEntryPoint.entryPoints.keySet() as List
			entryPoints[0].requestMatchers[1].contentNegotiationStrategy == OverrideContentNegotiationStrategySharedObjectConfig.CNS
			entryPoints[1].requestMatchers[1].requestMatchers[1].contentNegotiationStrategy == OverrideContentNegotiationStrategySharedObjectConfig.CNS
	}

	def "Override ContentNegotiationStrategy with @Bean"() {
		setup:
			OverrideContentNegotiationStrategySharedObjectConfig.CNS = Mock(ContentNegotiationStrategy)
		when:
			loadConfig(OverrideContentNegotiationStrategySharedObjectConfig)
		then:
			context.getBean(OverrideContentNegotiationStrategySharedObjectConfig).http.getSharedObject(ContentNegotiationStrategy) == OverrideContentNegotiationStrategySharedObjectConfig.CNS
	}

	@EnableWebSecurity
	static class OverrideContentNegotiationStrategySharedObjectConfig extends WebSecurityConfigurerAdapter {
		static ContentNegotiationStrategy CNS

		@Bean
		public static ContentNegotiationStrategy cns() {
			return CNS
		}
	}

	def "delegatingAuthenticationEntryPoint.defaultEntryPoint is LoginUrlAuthenticationEntryPoint when using DefaultHttpConf"() {
		when:
			loadConfig(DefaultHttpConf)
		then:
			findFilter(ExceptionTranslationFilter).authenticationEntryPoint.defaultEntryPoint.class == LoginUrlAuthenticationEntryPoint
	}

	@EnableWebSecurity
	static class DefaultHttpConf extends WebSecurityConfigurerAdapter {
	}

	def "delegatingAuthenticationEntryPoint.defaultEntryPoint is BasicAuthenticationEntryPoint when httpBasic before formLogin"() {
		when:
			loadConfig(BasicAuthenticationEntryPointBeforeFormLoginConf)
		then:
			findFilter(ExceptionTranslationFilter).authenticationEntryPoint.defaultEntryPoint.defaultEntryPoint.class == BasicAuthenticationEntryPoint
	}

	@EnableWebSecurity
	static class BasicAuthenticationEntryPointBeforeFormLoginConf extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.httpBasic()
					.and()
				.formLogin()
		}
	}

	def "invoke exceptionHandling twice does not override"() {
		setup:
			InvokeTwiceDoesNotOverrideConfig.AEP = Mock(AuthenticationEntryPoint)
		when:
			loadConfig(InvokeTwiceDoesNotOverrideConfig)
		then:
			findFilter(ExceptionTranslationFilter).authenticationEntryPoint == InvokeTwiceDoesNotOverrideConfig.AEP
	}

	@EnableWebSecurity
	static class InvokeTwiceDoesNotOverrideConfig extends WebSecurityConfigurerAdapter {
		static AuthenticationEntryPoint AEP
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.exceptionHandling()
					.authenticationEntryPoint(AEP)
					.and()
				.exceptionHandling()
		}
	}
}
