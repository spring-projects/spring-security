/*
 * Copyright 2002-2012 the original author or authors.
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

import static org.mockito.Matchers.any
import static org.mockito.Matchers.eq
import static org.mockito.Mockito.*

import javax.servlet.http.HttpServletResponse
import javax.servlet.http.HttpServletResponseWrapper

import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse

/**
 *
 * @author Rob Winch
 */
class HttpConfigTests extends AbstractHttpConfigTests {
	MockHttpServletRequest request = new MockHttpServletRequest('GET','/secure')
	MockHttpServletResponse response = new MockHttpServletResponse()
	MockFilterChain chain = new MockFilterChain()

	def 'http minimal configuration works'() {
		setup:
		xml.http() {}
		createAppContext("""<user-service>
		<user name="user" password="password" authorities="ROLE_USER" />
	</user-service>""")
		when: 'request protected URL'
		springSecurityFilterChain.doFilter(request,response,chain)
		then: 'sent to login page'
		response.status == HttpServletResponse.SC_MOVED_TEMPORARILY
		response.redirectedUrl == 'http://localhost/login'
	}

	def 'http disable-url-rewriting defaults to true'() {
		setup:
		xml.http() {}
		createAppContext("""<user-service>
		<user name="user" password="password" authorities="ROLE_USER" />
	</user-service>""")
		HttpServletResponse testResponse = new HttpServletResponseWrapper(response) {
			public String encodeURL(String url) {
				throw new RuntimeException("Unexpected invocation of encodeURL")
			}
			public String encodeRedirectURL(String url) {
				throw new RuntimeException("Unexpected invocation of encodeURL")
			}
			public String encodeUrl(String url) {
				throw new RuntimeException("Unexpected invocation of encodeURL")
			}
			public String encodeRedirectUrl(String url) {
				throw new RuntimeException("Unexpected invocation of encodeURL")
			}
		}
		when: 'request protected URL'
		springSecurityFilterChain.doFilter(request,testResponse,{ request,response->
			response.encodeURL("/url")
			response.encodeRedirectURL("/url")
			response.encodeUrl("/url")
			response.encodeRedirectUrl("/url")
		})
		then: 'sent to login page'
		response.status == HttpServletResponse.SC_MOVED_TEMPORARILY
		response.redirectedUrl == 'http://localhost/login'
	}
}