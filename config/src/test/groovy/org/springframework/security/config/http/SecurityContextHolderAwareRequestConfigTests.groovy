/*
 * Copyright 2002-2012 the original author or authors.
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
package org.springframework.security.config.http

import static org.springframework.security.config.ConfigTestUtils.AUTH_PROVIDER_XML

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter
import org.springframework.security.web.context.HttpSessionSecurityContextRepository
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter

/**
 *
 * @author Rob Winch
 */
class SecurityContextHolderAwareRequestConfigTests extends AbstractHttpConfigTests {

	def withAutoConfig() {
		httpAutoConfig () {
			csrf(disabled:true)
		}
		createAppContext(AUTH_PROVIDER_XML)

		def securityContextAwareFilter = getFilter(SecurityContextHolderAwareRequestFilter)

		expect:
		securityContextAwareFilter.authenticationEntryPoint.loginFormUrl == getFilter(ExceptionTranslationFilter).authenticationEntryPoint.loginFormUrl
		securityContextAwareFilter.authenticationManager == getFilter(UsernamePasswordAuthenticationFilter).authenticationManager
		securityContextAwareFilter.logoutHandlers.size() == 1
		securityContextAwareFilter.logoutHandlers[0].class == SecurityContextLogoutHandler
	}

	def explicitEntryPoint() {
		xml.http() {
			'http-basic'('entry-point-ref': 'ep')
		}
		bean('ep', BasicAuthenticationEntryPoint.class.name, ['realmName':'whocares'],[:])
		createAppContext(AUTH_PROVIDER_XML)

		def securityContextAwareFilter = getFilter(SecurityContextHolderAwareRequestFilter)

		expect:
		securityContextAwareFilter.authenticationEntryPoint == getFilter(ExceptionTranslationFilter).authenticationEntryPoint
		securityContextAwareFilter.authenticationManager == getFilter(BasicAuthenticationFilter).authenticationManager
		securityContextAwareFilter.logoutHandlers == null
	}

	def formLogin() {
		xml.http() {
			'form-login'()
		}
		createAppContext(AUTH_PROVIDER_XML)

		def securityContextAwareFilter = getFilter(SecurityContextHolderAwareRequestFilter)

		expect:
		securityContextAwareFilter.authenticationEntryPoint.loginFormUrl == getFilter(ExceptionTranslationFilter).authenticationEntryPoint.loginFormUrl
		securityContextAwareFilter.authenticationManager == getFilter(UsernamePasswordAuthenticationFilter).authenticationManager
		securityContextAwareFilter.logoutHandlers == null
	}

	def multiHttp() {
		xml.http('authentication-manager-ref' : 'authManager', 'pattern' : '/first/**') {
			'form-login'('login-page' : '/login')
			'logout'('invalidate-session' : 'true')
			csrf(disabled:true)
		}
		xml.http('authentication-manager-ref' : 'authManager2') {
			'form-login'('login-page' : '/login2')
			'logout'('invalidate-session' : 'false')
			csrf(disabled:true)
		}

		String secondAuthManager = AUTH_PROVIDER_XML.replace("alias='authManager'", "id='authManager2'")
		createAppContext(AUTH_PROVIDER_XML + secondAuthManager)

		def securityContextAwareFilter = getFilters('/first/filters').find { it instanceof SecurityContextHolderAwareRequestFilter }
		def secondSecurityContextAwareFilter = getFilter(SecurityContextHolderAwareRequestFilter)

		expect:
		securityContextAwareFilter.authenticationEntryPoint.loginFormUrl == '/login'
		securityContextAwareFilter.authenticationManager == getFilters('/first/filters').find { it instanceof UsernamePasswordAuthenticationFilter}.authenticationManager
		securityContextAwareFilter.authenticationManager.parent == appContext.getBean('authManager')
		securityContextAwareFilter.logoutHandlers.size() == 1
		securityContextAwareFilter.logoutHandlers[0].class == SecurityContextLogoutHandler
		securityContextAwareFilter.logoutHandlers[0].invalidateHttpSession == true

		secondSecurityContextAwareFilter.authenticationEntryPoint.loginFormUrl == '/login2'
		secondSecurityContextAwareFilter.authenticationManager == getFilter(UsernamePasswordAuthenticationFilter).authenticationManager
		secondSecurityContextAwareFilter.authenticationManager.parent == appContext.getBean('authManager2')
		securityContextAwareFilter.logoutHandlers.size() == 1
		secondSecurityContextAwareFilter.logoutHandlers[0].class == SecurityContextLogoutHandler
		secondSecurityContextAwareFilter.logoutHandlers[0].invalidateHttpSession == false
	}

	def logoutCustom() {
		xml.http() {
			'form-login'('login-page' : '/login')
			'logout'('invalidate-session' : 'false', 'logout-success-url' : '/login?logout', 'delete-cookies' : 'JSESSIONID')
			csrf(disabled:true)
		}
		createAppContext(AUTH_PROVIDER_XML)

		def securityContextAwareFilter = getFilter(SecurityContextHolderAwareRequestFilter)

		expect:
		securityContextAwareFilter.authenticationEntryPoint.loginFormUrl == getFilter(ExceptionTranslationFilter).authenticationEntryPoint.loginFormUrl
		securityContextAwareFilter.authenticationManager == getFilter(UsernamePasswordAuthenticationFilter).authenticationManager
		securityContextAwareFilter.logoutHandlers.size() == 2
		securityContextAwareFilter.logoutHandlers[0].class == SecurityContextLogoutHandler
		securityContextAwareFilter.logoutHandlers[0].invalidateHttpSession == false
		securityContextAwareFilter.logoutHandlers[1].class == CookieClearingLogoutHandler
		securityContextAwareFilter.logoutHandlers[1].cookiesToClear == ['JSESSIONID']
	}

	def 'SEC-2926: Role Prefix is set'() {
		setup:
		httpAutoConfig () {

		}
		createAppContext(AUTH_PROVIDER_XML)

		MockFilterChain chain = new MockFilterChain() {
			public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
				assert request.isUserInRole("USER")

				super.doFilter(request,response)
			}
		}
		MockHttpServletRequest request = new MockHttpServletRequest(method:'GET')
		SecurityContext context = SecurityContextHolder.createEmptyContext()
		context.setAuthentication(new TestingAuthenticationToken("user", "pass", "ROLE_USER"))
		request.getSession().setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context)

		when:
		springSecurityFilterChain.doFilter(request, new MockHttpServletResponse(), chain)
		then:
		chain.request != null
	}
}
