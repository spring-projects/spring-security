/*
 * Copyright 2002-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *		https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.http

import javax.servlet.ServletContext
import javax.servlet.ServletRegistration
import javax.servlet.http.HttpServletResponse

import org.mockito.invocation.InvocationOnMock
import org.mockito.stubbing.Answer

import org.springframework.beans.factory.parsing.BeanDefinitionParsingException
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.mock.web.MockServletContext
import org.springframework.security.access.SecurityConfig
import org.springframework.security.crypto.codec.Base64
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

import static org.mockito.Mockito.*
/**
 *
 * @author Rob Winch
 */
class InterceptUrlConfigTests extends AbstractHttpConfigTests {

	def "SEC-2256: intercept-url method is not given priority"() {
		when:
		httpAutoConfig {
			'intercept-url'(pattern: '/anyurl', access: "ROLE_USER")
			'intercept-url'(pattern: '/anyurl', 'method':'GET',access: 'ROLE_ADMIN')
		}
		createAppContext()

		def fids = getFilter(FilterSecurityInterceptor).securityMetadataSource
		def attrs = fids.getAttributes(createFilterinvocation("/anyurl", "GET"))
		def attrsPost = fids.getAttributes(createFilterinvocation("/anyurl", "POST"))

		then:
		attrs.size() == 1
		attrs.contains(new SecurityConfig("ROLE_USER"))
		attrsPost.size() == 1
		attrsPost.contains(new SecurityConfig("ROLE_USER"))
	}

	def "SEC-2355: intercept-url support patch"() {
		setup:
		MockHttpServletRequest request = new MockHttpServletRequest(method:'GET')
		MockHttpServletResponse response = new MockHttpServletResponse()
		MockFilterChain chain = new MockFilterChain()
		xml.http('use-expressions':false) {
			'http-basic'()
			'intercept-url'(pattern: '/**', 'method':'PATCH',access: 'ROLE_ADMIN')
			csrf(disabled:true)
		}
		createAppContext()
		when: 'Method other than PATCH is used'
		springSecurityFilterChain.doFilter(request,response,chain)
		then: 'The response is OK'
		response.status == HttpServletResponse.SC_OK
		when: 'Method of PATCH is used'
		request = new MockHttpServletRequest(method:'PATCH')
		response = new MockHttpServletResponse()
		chain = new MockFilterChain()
		springSecurityFilterChain.doFilter(request, response, chain)
		then: 'The response is unauthorized'
		response.status == HttpServletResponse.SC_UNAUTHORIZED
	}

	def "intercept-url supports hasAnyRoles"() {
		setup:
		MockHttpServletRequest request = new MockHttpServletRequest(method:'GET')
		MockHttpServletResponse response = new MockHttpServletResponse()
		MockFilterChain chain = new MockFilterChain()
		xml.http('use-expressions':true) {
			'http-basic'()
			'intercept-url'(pattern: '/**', access: "hasAnyRole('ROLE_DEVELOPER','ROLE_USER')")
			csrf(disabled:true)
		}
		when:
		createAppContext()
		then: 'no error'
		noExceptionThrown()
		when: 'ROLE_USER can access'
		login(request, 'user', 'password')
		springSecurityFilterChain.doFilter(request,response,chain)
		then: 'The response is OK'
		response.status == HttpServletResponse.SC_OK
		when: 'ROLE_A cannot access'
		request = new MockHttpServletRequest(method:'GET')
		response = new MockHttpServletResponse()
		chain = new MockFilterChain()
		login(request, 'bob', 'bobspassword')
		springSecurityFilterChain.doFilter(request,response,chain)
		then: 'The response is Forbidden'
		response.status == HttpServletResponse.SC_FORBIDDEN
	}

	def "SEC-2256: intercept-url supports path variables"() {
		setup:
		MockHttpServletRequest request = new MockHttpServletRequest(method:'GET')
		MockHttpServletResponse response = new MockHttpServletResponse()
		MockFilterChain chain = new MockFilterChain()
		xml.http('use-expressions':true) {
			'http-basic'()
			'intercept-url'(pattern: '/user/{un}/**', access: "#un == authentication.name")
			'intercept-url'(pattern: '/**', access: "denyAll")
		}
		createAppContext()
		login(request, 'user', 'password')
		when: 'user can access'
		request.servletPath = '/user/user/abc'
		springSecurityFilterChain.doFilter(request,response,chain)
		then: 'The response is OK'
		response.status == HttpServletResponse.SC_OK
		when: 'user cannot access otheruser'
		request = new MockHttpServletRequest(method:'GET', servletPath : '/user/otheruser/abc')
		login(request, 'user', 'password')
		chain.reset()
		springSecurityFilterChain.doFilter(request,response,chain)
		then: 'The response is OK'
		response.status == HttpServletResponse.SC_FORBIDDEN
		when: 'user can access case insensitive URL'
		request = new MockHttpServletRequest(method:'GET', servletPath : '/USER/user/abc')
		login(request, 'user', 'password')
		chain.reset()
		springSecurityFilterChain.doFilter(request,response,chain)
		then: 'The response is OK'
		response.status == HttpServletResponse.SC_FORBIDDEN
	}

	def "gh-3786 intercept-url supports cammel case path variables"() {
		setup:
		MockHttpServletRequest request = new MockHttpServletRequest(method:'GET')
		MockHttpServletResponse response = new MockHttpServletResponse()
		MockFilterChain chain = new MockFilterChain()
		xml.http('use-expressions':true) {
			'http-basic'()
			'intercept-url'(pattern: '/user/{userName}/**', access: "#userName == authentication.name")
			'intercept-url'(pattern: '/**', access: "denyAll")
		}
		createAppContext()
		login(request, 'user', 'password')
		when: 'user can access'
		request.servletPath = '/user/user/abc'
		springSecurityFilterChain.doFilter(request,response,chain)
		then: 'The response is OK'
		response.status == HttpServletResponse.SC_OK
		when: 'user cannot access otheruser'
		request = new MockHttpServletRequest(method:'GET', servletPath : '/user/otheruser/abc')
		login(request, 'user', 'password')
		chain.reset()
		springSecurityFilterChain.doFilter(request,response,chain)
		then: 'The response is OK'
		response.status == HttpServletResponse.SC_FORBIDDEN
		when: 'user can access case insensitive URL'
		request = new MockHttpServletRequest(method:'GET', servletPath : '/USER/user/abc')
		login(request, 'user', 'password')
		chain.reset()
		springSecurityFilterChain.doFilter(request,response,chain)
		then: 'The response is OK'
		response.status == HttpServletResponse.SC_FORBIDDEN
	}

	def "SEC-2256: intercept-url supports path variable type conversion"() {
		setup:
		MockHttpServletRequest request = new MockHttpServletRequest(method:'GET')
		MockHttpServletResponse response = new MockHttpServletResponse()
		MockFilterChain chain = new MockFilterChain()
		xml.http('use-expressions':true) {
			'http-basic'()
			'intercept-url'(pattern: '/user/{un}/**', access: "@id.isOne(#un)")
			'intercept-url'(pattern: '/**', access: "denyAll")
		}
		bean('id', Id)
		createAppContext()
		login(request, 'user', 'password')
		when: 'can access id == 1'
		request.servletPath = '/user/1/abc'
		springSecurityFilterChain.doFilter(request,response,chain)
		then: 'The response is OK'
		response.status == HttpServletResponse.SC_OK
		when: 'user cannot access 2'
		request = new MockHttpServletRequest(method:'GET', servletPath : '/user/2/abc')
		login(request, 'user', 'password')
		chain.reset()
		springSecurityFilterChain.doFilter(request,response,chain)
		then: 'The response is OK'
		response.status == HttpServletResponse.SC_FORBIDDEN
	}

	def "intercept-url supports mvc matchers"() {
		setup:
		MockServletContext servletContext = mockServletContext();
		MockHttpServletRequest request = new MockHttpServletRequest(method:'GET')
		MockHttpServletResponse response = new MockHttpServletResponse()
		MockFilterChain chain = new MockFilterChain()
		xml.http('request-matcher':'mvc') {
			'http-basic'()
			'intercept-url'(pattern: '/path', access: "denyAll")
		}
		bean('pathController',PathController)
		xml.'mvc:annotation-driven'()

		createWebAppContext(servletContext)
		when:
		request.servletPath = "/path"
		springSecurityFilterChain.doFilter(request, response, chain)
		then:
		response.status == HttpServletResponse.SC_UNAUTHORIZED
		when:
		request = new MockHttpServletRequest(method:'GET')
		response = new MockHttpServletResponse()
		chain = new MockFilterChain()
		request.servletPath = "/path.html"
		springSecurityFilterChain.doFilter(request, response, chain)
		then:
		response.status == HttpServletResponse.SC_UNAUTHORIZED
		when:
		request = new MockHttpServletRequest(method:'GET')
		response = new MockHttpServletResponse()
		chain = new MockFilterChain()
		request.servletPath = "/path/"
		springSecurityFilterChain.doFilter(request, response, chain)
		then:
		response.status == HttpServletResponse.SC_UNAUTHORIZED
	}

	def "intercept-url mvc supports path variables"() {
		setup:
		MockServletContext servletContext = mockServletContext();
		MockHttpServletRequest request = new MockHttpServletRequest(method:'GET')
		MockHttpServletResponse response = new MockHttpServletResponse()
		MockFilterChain chain = new MockFilterChain()
		xml.http('request-matcher':'mvc') {
			'http-basic'()
			'intercept-url'(pattern: '/user/{un}/**', access: "#un == 'user'")
		}
		xml.'mvc:annotation-driven'()
		createWebAppContext(servletContext)
		when: 'user can access'
		request.servletPath = '/user/user/abc'
		springSecurityFilterChain.doFilter(request,response,chain)
		then: 'The response is OK'
		response.status == HttpServletResponse.SC_OK
		when: 'cannot access otheruser'
		request = new MockHttpServletRequest(method:'GET', servletPath : '/user/otheruser/abc')
		login(request, 'user', 'password')
		chain.reset()
		springSecurityFilterChain.doFilter(request,response,chain)
		then: 'The response is OK'
		response.status == HttpServletResponse.SC_FORBIDDEN
		when: 'user can access case insensitive URL'
		request = new MockHttpServletRequest(method:'GET', servletPath : '/USER/user/abc')
		login(request, 'user', 'password')
		chain.reset()
		springSecurityFilterChain.doFilter(request,response,chain)
		then: 'The response is OK'
		response.status == HttpServletResponse.SC_FORBIDDEN
	}

	def "intercept-url mvc matchers with servlet path"() {
		setup:
		MockServletContext servletContext = mockServletContext("/spring");
		MockHttpServletRequest request = new MockHttpServletRequest(method:'GET')
		MockHttpServletResponse response = new MockHttpServletResponse()
		MockFilterChain chain = new MockFilterChain()
		xml.http('request-matcher':'mvc') {
			'http-basic'()
			'intercept-url'(pattern: '/path', access: "denyAll", 'servlet-path': "/spring")
		}
		bean('pathController',PathController)
		xml.'mvc:annotation-driven'()
		createWebAppContext(servletContext)
		when:
		request.servletPath = "/spring"
		request.requestURI = "/spring/path"
		springSecurityFilterChain.doFilter(request, response, chain)
		then:
		response.status == HttpServletResponse.SC_UNAUTHORIZED
		when:
		request = new MockHttpServletRequest(method:'GET')
		response = new MockHttpServletResponse()
		chain = new MockFilterChain()
		request.servletPath = "/spring"
		request.requestURI = "/spring/path.html"
		springSecurityFilterChain.doFilter(request, response, chain)
		then:
		response.status == HttpServletResponse.SC_UNAUTHORIZED
		when:
		request = new MockHttpServletRequest(method:'GET')
		response = new MockHttpServletResponse()
		chain = new MockFilterChain()
		request.servletPath = "/spring"
		request.requestURI = "/spring/path/"
		springSecurityFilterChain.doFilter(request, response, chain)
		then:
		response.status == HttpServletResponse.SC_UNAUTHORIZED
	}

	def "intercept-url ant matcher with servlet path fails"() {
		when:
		xml.http('request-matcher':'ant') {
			'http-basic'()
			'intercept-url'(pattern: '/path', access: "denyAll", 'servlet-path': "/spring")
		}
		createAppContext()
		then:
		thrown(BeanDefinitionParsingException)
	}

	def "intercept-url regex matcher with servlet path fails"() {
		when:
		xml.http('request-matcher':'regex') {
			'http-basic'()
			'intercept-url'(pattern: '/path', access: "denyAll", 'servlet-path': "/spring")
		}
		createAppContext()
		then:
		thrown(BeanDefinitionParsingException)
	}

	def "intercept-url ciRegex matcher with servlet path fails"() {
		when:
		xml.http('request-matcher':'ciRegex') {
			'http-basic'()
			'intercept-url'(pattern: '/path', access: "denyAll", 'servlet-path': "/spring")
		}
		createAppContext()
		then:
		thrown(BeanDefinitionParsingException)
	}

	def "intercept-url default matcher with servlet path fails"() {
		when:
		xml.http() {
			'http-basic'()
			'intercept-url'(pattern: '/path', access: "denyAll", 'servlet-path': "/spring")
		}
		createAppContext()
		then:
		thrown(BeanDefinitionParsingException)
	}

	public static class Id {
		public boolean isOne(int i) {
			return i == 1;
		}
	}

	private ServletContext mockServletContext() {
		return mockServletContext("/");
	}

	private ServletContext mockServletContext(String servletPath) {
		MockServletContext servletContext = spy(new MockServletContext());
		final ServletRegistration registration = mock(ServletRegistration.class);
		when(registration.getMappings()).thenReturn(Collections.singleton(servletPath));
		Answer<Map<String, ? extends ServletRegistration>> answer = new Answer<Map<String, ? extends ServletRegistration>>() {
			@Override
			public Map<String, ? extends ServletRegistration> answer(InvocationOnMock invocation) throws Throwable {
				return Collections.<String, ServletRegistration>singletonMap("spring", registration);
			}
		};
		when(servletContext.getServletRegistrations()).thenAnswer(answer);
		return servletContext;
	}

	def login(MockHttpServletRequest request, String username, String password) {
		String toEncode = username + ':' + password
		request.addHeader('Authorization','Basic ' + new String(Base64.encode(toEncode.getBytes('UTF-8'))))
	}

	@RestController
	static class PathController {
		@RequestMapping("/path")
		public String path() {
			return "path";
		}
	}
}
