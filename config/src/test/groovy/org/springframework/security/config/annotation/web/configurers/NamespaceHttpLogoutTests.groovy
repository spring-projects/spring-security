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
package org.springframework.security.config.annotation.web.configurers;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.access.AccessDecisionManager
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute
import org.springframework.security.authentication.AnonymousAuthenticationToken
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.BaseWebConfig;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextImpl
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.FilterChainProxy
import org.springframework.security.web.FilterInvocation
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.HttpRequestResponseHolder
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextPersistenceFilter
import org.springframework.security.web.jaasapi.JaasApiIntegrationFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher

/**
 * Tests to verify that all the functionality of <logout> attributes is present
 *
 * @author Rob Winch
 *
 */
public class NamespaceHttpLogoutTests extends BaseSpringSpec {

	def "http/logout"() {
		setup:
			loadConfig(HttpLogoutConfig)
			login()
			request.servletPath = "/logout"
			request.method = "POST"
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			!authenticated()
			!request.getSession(false)
			response.redirectedUrl == "/login?logout"
			!response.getCookies()
	}

	@Configuration
	static class HttpLogoutConfig extends BaseWebConfig {
		protected void configure(HttpSecurity http) throws Exception {
		}
	}

	def "http/logout custom"() {
		setup:
			loadConfig(CustomHttpLogoutConfig)
			login()
			request.servletPath = "/custom-logout"
			request.method = "POST"
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			!authenticated()
			request.getSession(false)
			response.redirectedUrl == "/logout-success"
			response.getCookies().length == 1
			response.getCookies()[0].name == "remove"
			response.getCookies()[0].maxAge == 0
	}

	@Configuration
	static class CustomHttpLogoutConfig extends BaseWebConfig {
		protected void configure(HttpSecurity http) throws Exception {
			http
				.logout()
					.deleteCookies("remove") // logout@delete-cookies
					.invalidateHttpSession(false) // logout@invalidate-session=false (default is true)
					.logoutUrl("/custom-logout") // logout@logout-url (default is /logout)
					.logoutSuccessUrl("/logout-success") // logout@success-url (default is /login?logout)
		}
	}

	def "http/logout@success-handler-ref"() {
		setup:
			loadConfig(SuccessHandlerRefHttpLogoutConfig)
			login()
			request.servletPath = "/logout"
			request.method = "POST"
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			!authenticated()
			!request.getSession(false)
			response.redirectedUrl == "/SuccessHandlerRefHttpLogoutConfig"
			!response.getCookies()
	}

	@Configuration
	static class SuccessHandlerRefHttpLogoutConfig extends BaseWebConfig {
		protected void configure(HttpSecurity http) throws Exception {
			SimpleUrlLogoutSuccessHandler logoutSuccessHandler = new SimpleUrlLogoutSuccessHandler(defaultTargetUrl:"/SuccessHandlerRefHttpLogoutConfig")
			http
				.logout()
					.logoutSuccessHandler(logoutSuccessHandler)
		}
	}

	def login(String username="user", String role="ROLE_USER") {
		HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository()
		HttpRequestResponseHolder requestResponseHolder = new HttpRequestResponseHolder(request, response)
		repo.loadContext(requestResponseHolder)
		repo.saveContext(new SecurityContextImpl(authentication: new UsernamePasswordAuthenticationToken(username, null, AuthorityUtils.createAuthorityList(role))), requestResponseHolder.request, requestResponseHolder.response)
	}

	def authenticated() {
		HttpRequestResponseHolder requestResponseHolder = new HttpRequestResponseHolder(request, response)
		new HttpSessionSecurityContextRepository().loadContext(requestResponseHolder)?.authentication?.authenticated
	}
}
