/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.config.http

import org.springframework.beans.factory.BeanCreationException

import javax.servlet.http.HttpServletResponse

import org.springframework.http.*
import org.springframework.mock.web.*
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint
import org.springframework.web.bind.annotation.*
import org.springframework.web.filter.CorsFilter
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.UrlBasedCorsConfigurationSource

/**
 *
 * @author Rob Winch
 * @author Tim Ysewyn
 */
class HttpCorsConfigTests extends AbstractHttpConfigTests {
	MockHttpServletRequest request
	MockHttpServletResponse response
	MockFilterChain chain

	def setup() {
		request = new MockHttpServletRequest(method:"GET")
		response = new MockHttpServletResponse()
		chain = new MockFilterChain()
	}

	def "No MVC throws meaningful error"() {
		when:
		xml.http('entry-point-ref' : 'ep') {
			'cors'()
			'intercept-url'(pattern:'/**', access: 'authenticated')
		}
		bean('ep', Http403ForbiddenEntryPoint)
		createAppContext()
		then:
		BeanCreationException success = thrown()
		success.message.contains("Please ensure Spring Security & Spring MVC are configured in a shared ApplicationContext")
	}

	def "HandlerMappingIntrospector explicit"() {
		setup:
		xml.http('entry-point-ref' : 'ep') {
			'cors'()
			'intercept-url'(pattern:'/**', access: 'authenticated')
		}
		bean('ep', Http403ForbiddenEntryPoint)
		bean('controller', CorsController)
		xml.'mvc:annotation-driven'()
		createAppContext()
		when:
		addCors()
		springSecurityFilterChain.doFilter(request,response,chain)
		then: 'Ensure we a CORS response w/ Spring Security headers too'
		responseHeaders['Access-Control-Allow-Origin']
		responseHeaders['X-Content-Type-Options']
		when:
		setup()
		addCors(true)
		springSecurityFilterChain.doFilter(request,response,chain)
		then: 'Ensure we a CORS response w/ Spring Security headers too'
		responseHeaders['Access-Control-Allow-Origin']
		responseHeaders['X-Content-Type-Options']
		response.status == HttpServletResponse.SC_OK
	}

	def "CorsConfigurationSource"() {
		setup:
		xml.http('entry-point-ref' : 'ep') {
			'cors'('configuration-source-ref':'ccs')
			'intercept-url'(pattern:'/**', access: 'authenticated')
		}
		bean('ep', Http403ForbiddenEntryPoint)
		bean('ccs', MyCorsConfigurationSource)
		createAppContext()
		when:
		addCors()
		springSecurityFilterChain.doFilter(request,response,chain)
		then: 'Ensure we a CORS response w/ Spring Security headers too'
		responseHeaders['Access-Control-Allow-Origin']
		responseHeaders['X-Content-Type-Options']
		when:
		setup()
		addCors(true)
		springSecurityFilterChain.doFilter(request,response,chain)
		then: 'Ensure we a CORS response w/ Spring Security headers too'
		responseHeaders['Access-Control-Allow-Origin']
		responseHeaders['X-Content-Type-Options']
		response.status == HttpServletResponse.SC_OK
	}

	def "CorsFilter"() {
		setup:
		xml.http('entry-point-ref' : 'ep') {
			'cors'('ref' : 'cf')
			'intercept-url'(pattern:'/**', access: 'authenticated')
		}
		xml.'b:bean'(id: 'cf', 'class': CorsFilter.name) {
			'b:constructor-arg'(ref: 'ccs')
		}
		bean('ep', Http403ForbiddenEntryPoint)
		bean('ccs', MyCorsConfigurationSource)
		createAppContext()
		when:
		addCors()
		springSecurityFilterChain.doFilter(request,response,chain)
		then: 'Ensure we a CORS response w/ Spring Security headers too'
		responseHeaders['Access-Control-Allow-Origin']
		responseHeaders['X-Content-Type-Options']
		when:
		setup()
		addCors(true)
		springSecurityFilterChain.doFilter(request,response,chain)
		then: 'Ensure we a CORS response w/ Spring Security headers too'
		responseHeaders['Access-Control-Allow-Origin']
		responseHeaders['X-Content-Type-Options']
		response.status == HttpServletResponse.SC_OK
	}

	def addCors(boolean isPreflight=false) {
		request.addHeader(HttpHeaders.ORIGIN,"https://example.com")
		if(!isPreflight) {
			return
		}
		request.method = HttpMethod.OPTIONS.name()
		request.addHeader(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, HttpMethod.POST.name())
	}

	def getResponseHeaders() {
		def headers = [:]
		response.headerNames.each { name ->
			headers.put(name, response.getHeaderValues(name).join(','))
		}
		return headers
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

	static class MyCorsConfigurationSource extends UrlBasedCorsConfigurationSource {
		MyCorsConfigurationSource() {
			registerCorsConfiguration('/**', new CorsConfiguration(allowedOrigins : ['*'], allowedMethods : [
				RequestMethod.GET.name(),
				RequestMethod.POST.name()
			]))
		}
	}
}
