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
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.config.annotation.AnyObjectPostProcessor
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.session.SessionDestroyedEvent
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.authentication.session.CompositeSessionAuthenticationStrategy
import org.springframework.security.web.authentication.session.ConcurrentSessionControlAuthenticationStrategy
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy
import org.springframework.security.web.context.NullSecurityContextRepository
import org.springframework.security.web.context.SecurityContextPersistenceFilter
import org.springframework.security.web.context.SecurityContextRepository
import org.springframework.security.web.savedrequest.RequestCache
import org.springframework.security.web.session.ConcurrentSessionFilter
import org.springframework.security.web.session.HttpSessionDestroyedEvent;
import org.springframework.security.web.session.SessionManagementFilter

import spock.lang.Unroll;

/**
 *
 * @author Rob Winch
 */
class RequestMatcherConfigurerTests extends BaseSpringSpec {


	@Unroll
	def "SEC-2908 - multiple invocations of authorizeRequests() chains #path"(def path) {
		setup:
			loadConfig(Sec2908Config)
			request.servletPath = path
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			response.status == HttpServletResponse.SC_FORBIDDEN
		where:
			path << ['/oauth/abc','/api/abc']
	}

	@Configuration
	@EnableWebSecurity
	static class Sec2908Config extends WebSecurityConfigurerAdapter {

		 @Override
		 protected void configure(HttpSecurity http) throws Exception {
			 http
				.requestMatchers()
					.antMatchers("/api/**")
					.and()
				 .requestMatchers()
					.antMatchers("/oauth/**")
					.and()
				 .authorizeRequests()
					.anyRequest().denyAll();
		}
	}
}
