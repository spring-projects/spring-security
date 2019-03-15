/*
 * Copyright 2002-2016 the original author or authors.
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

import org.springframework.beans.factory.BeanCreationException
import org.springframework.beans.factory.NoSuchBeanDefinitionException

import javax.servlet.http.HttpServletResponse

import org.springframework.context.annotation.Bean
import org.springframework.http.*
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.web.bind.annotation.*
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource
import org.springframework.web.filter.CorsFilter
import org.springframework.web.servlet.config.annotation.EnableWebMvc

/**
 *
 * @author Rob Winch
 */
class CorsConfigurerTests extends BaseSpringSpec {

	def "No MVC throws meaningful error"() {
		when:
		loadConfig(DefaultCorsConfig)
		then:
		BeanCreationException success = thrown()
		success.message.contains("Please ensure Spring Security & Spring MVC are configured in a shared ApplicationContext")
	}

	@EnableWebSecurity
	static class DefaultCorsConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.authorizeRequests()
					.anyRequest().authenticated()
					.and()
					.cors()
		}
	}

	def "HandlerMappingIntrospector explicit"() {
		setup:
		loadConfig(MvcCorsConfig)
		when:
		addCors()
		springSecurityFilterChain.doFilter(request,response,chain)
		then: 'Ensure we a CORS response w/ Spring Security headers too'
		responseHeaders['Access-Control-Allow-Origin']
		responseHeaders['X-Content-Type-Options']
		when:
		setupWeb()
		addCors(true)
		springSecurityFilterChain.doFilter(request,response,chain)
		then: 'Ensure we a CORS response w/ Spring Security headers too'
		responseHeaders['Access-Control-Allow-Origin']
		responseHeaders['X-Content-Type-Options']
		response.status == HttpServletResponse.SC_OK
	}

	@EnableWebMvc
	@EnableWebSecurity
	static class MvcCorsConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.authorizeRequests()
					.anyRequest().authenticated()
					.and()
					.cors()
		}

		@RestController
		@CrossOrigin(methods = [
			RequestMethod.GET, RequestMethod.POST
		])
		static class CorsController {
			@RequestMapping("/")
			String hello() {
				"Hello"
			}
		}
	}

	def "CorsConfigurationSource"() {
		setup:
		loadConfig(ConfigSourceConfig)
		when:
		addCors()
		springSecurityFilterChain.doFilter(request,response,chain)
		then: 'Ensure we a CORS response w/ Spring Security headers too'
		responseHeaders['Access-Control-Allow-Origin']
		responseHeaders['X-Content-Type-Options']
		when:
		setupWeb()
		addCors(true)
		springSecurityFilterChain.doFilter(request,response,chain)
		then: 'Ensure we a CORS response w/ Spring Security headers too'
		responseHeaders['Access-Control-Allow-Origin']
		responseHeaders['X-Content-Type-Options']
		response.status == HttpServletResponse.SC_OK
	}


	@EnableWebSecurity
	static class ConfigSourceConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.authorizeRequests()
					.anyRequest().authenticated()
					.and()
					.cors()
		}

		@Bean
		CorsConfigurationSource corsConfigurationSource() {
			UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource()
			source.registerCorsConfiguration("/**", new CorsConfiguration(allowedOrigins : ['*'], allowedMethods : [
				RequestMethod.GET.name(),
				RequestMethod.POST.name()
			]))
			source
		}
	}

	def "CorsFilter"() {
		setup:
		loadConfig(CorsFilterConfig)
		when:
		addCors()
		springSecurityFilterChain.doFilter(request,response,chain)
		then: 'Ensure we a CORS response w/ Spring Security headers too'
		responseHeaders['Access-Control-Allow-Origin']
		responseHeaders['X-Content-Type-Options']
		when:
		setupWeb()
		addCors(true)
		springSecurityFilterChain.doFilter(request,response,chain)
		then: 'Ensure we a CORS response w/ Spring Security headers too'
		responseHeaders['Access-Control-Allow-Origin']
		responseHeaders['X-Content-Type-Options']
		response.status == HttpServletResponse.SC_OK
	}


	@EnableWebSecurity
	static class CorsFilterConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.authorizeRequests()
					.anyRequest().authenticated()
					.and()
					.cors()
		}

		@Bean
		CorsFilter corsFilter() {
			UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource()
			source.registerCorsConfiguration("/**", new CorsConfiguration(allowedOrigins : ['*'], allowedMethods : [
				RequestMethod.GET.name(),
				RequestMethod.POST.name()
			]))
			new CorsFilter(source)
		}
	}

	def addCors(boolean isPreflight=false) {
		request.addHeader(HttpHeaders.ORIGIN,"https://example.com")
		if(!isPreflight) {
			return
		}
		request.method = HttpMethod.OPTIONS.name()
		request.addHeader(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, HttpMethod.POST.name())
	}
}
