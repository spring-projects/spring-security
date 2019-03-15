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

import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextImpl
import org.springframework.security.web.FilterChainProxy
import org.springframework.security.web.context.HttpRequestResponseHolder
import org.springframework.security.web.context.HttpSessionSecurityContextRepository

/**
 * Tests to verify that all the functionality of <intercept-url> attributes is present
 *
 * @author Rob Winch
 *
 */
public class NamespaceHttpInterceptUrlTests extends BaseSpringSpec {

	def "http/intercept-url denied when not logged in"() {
		setup:
			loadConfig(HttpInterceptUrlConfig)
			request.servletPath == "/users"
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			response.status == HttpServletResponse.SC_FORBIDDEN
	}

	def "http/intercept-url denied when logged in"() {
		setup:
			loadConfig(HttpInterceptUrlConfig)
			login()
			request.setServletPath("/users")
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			response.status == HttpServletResponse.SC_FORBIDDEN
	}

	def "http/intercept-url allowed when logged in"() {
		setup:
			loadConfig(HttpInterceptUrlConfig)
			login("admin","ROLE_ADMIN")
			request.setServletPath("/users")
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			response.status == HttpServletResponse.SC_OK
			!response.isCommitted()
	}

	def "http/intercept-url@method=POST"() {
		setup:
			loadConfig(HttpInterceptUrlConfig)
		when:
			login()
			request.setServletPath("/admin/post")
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			response.status == HttpServletResponse.SC_OK
			!response.isCommitted()
		when:
			super.setup()
			login()
			request.setServletPath("/admin/post")
			request.setMethod("POST")
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			response.status == HttpServletResponse.SC_FORBIDDEN
		when:
			super.setup()
			login("admin","ROLE_ADMIN")
			request.setServletPath("/admin/post")
			request.setMethod("POST")
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			response.status == HttpServletResponse.SC_OK
			!response.committed
	}

	def "http/intercept-url@requires-channel"() {
		setup:
			loadConfig(HttpInterceptUrlConfig)
		when:
			request.setServletPath("/login")
			request.setRequestURI("/login")
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			response.redirectedUrl == "https://localhost/login"
		when:
			super.setup()
			request.setServletPath("/secured/a")
			request.setRequestURI("/secured/a")
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			response.redirectedUrl == "https://localhost/secured/a"
		when:
			super.setup()
			request.setSecure(true)
			request.setScheme("https")
			request.setServletPath("/user")
			request.setRequestURI("/user")
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			response.redirectedUrl == "http://localhost/user"
	}

	@EnableWebSecurity
	static class HttpInterceptUrlConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					// the line below is similar to intercept-url@pattern:
					//    <intercept-url pattern="/users**" access="hasRole('ROLE_ADMIN')"/>
					//    <intercept-url pattern="/sessions/**" access="hasRole('ROLE_ADMIN')"/>
					.antMatchers("/users**","/sessions/**").hasRole("ADMIN")
					// the line below is similar to intercept-url@method:
					//    <intercept-url pattern="/admin/post" access="hasRole('ROLE_ADMIN')" method="POST"/>
					//    <intercept-url pattern="/admin/another-post/**" access="hasRole('ROLE_ADMIN')" method="POST"/>
					.antMatchers(HttpMethod.POST, "/admin/post","/admin/another-post/**").hasRole("ADMIN")
					.antMatchers("/signup").permitAll()
					.anyRequest().hasRole("USER")
					.and()
				.requiresChannel()
					// NOTE: channel security is configured separately of authorization (i.e. intercept-url@access
					// the line below is similar to intercept-url@requires-channel="https":
					//    <intercept-url pattern="/login" requires-channel="https"/>
					//    <intercept-url pattern="/secured/**" requires-channel="https"/>
					.antMatchers("/login","/secured/**").requiresSecure()
					// the line below is similar to intercept-url@requires-channel="http":
					//    <intercept-url pattern="/**" requires-channel="http"/>
					.anyRequest().requiresInsecure()
		}
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
				.inMemoryAuthentication()
					.withUser("user").password("password").roles("USER").and()
					.withUser("admin").password("password").roles("USER", "ADMIN")
		}
	}
}
