/*
 * Copyright 2002-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.config.http

import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.context.SecurityContextImpl
import org.springframework.security.web.access.AccessDeniedHandler
import org.springframework.security.web.context.HttpRequestResponseHolder
import org.springframework.security.web.context.HttpSessionSecurityContextRepository
import org.springframework.security.web.csrf.CsrfFilter
import org.springframework.security.web.csrf.CsrfToken
import org.springframework.security.web.csrf.CsrfTokenRepository
import org.springframework.security.web.csrf.DefaultCsrfToken
import org.springframework.security.web.util.matcher.RequestMatcher
import org.springframework.web.servlet.support.RequestDataValueProcessor
import spock.lang.Unroll

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import static org.mockito.Matchers.any
import static org.mockito.Matchers.eq
import static org.mockito.Mockito.*

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
}