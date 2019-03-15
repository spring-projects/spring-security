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

import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.AnyObjectPostProcessor
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.web.context.SecurityContextPersistenceFilter
import org.springframework.security.web.context.SecurityContextRepository
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter

/**
 *
 * @author Rob Winch
 */
class SecurityContextConfigurerTests extends BaseSpringSpec {

	def "securityContext ObjectPostProcessor"() {
		setup:
			AnyObjectPostProcessor opp = Mock()
			HttpSecurity http = new HttpSecurity(opp, authenticationBldr, [:])
		when:
			http
				.securityContext()
					.and()
				.build()

		then: "SecurityContextPersistenceFilter is registered with LifecycleManager"
			1 * opp.postProcess(_ as SecurityContextPersistenceFilter) >> {SecurityContextPersistenceFilter o -> o}
	}

	def "invoke securityContext twice does not override"() {
		setup:
			InvokeTwiceDoesNotOverrideConfig.SCR = Mock(SecurityContextRepository)
		when:
			loadConfig(InvokeTwiceDoesNotOverrideConfig)
		then:
			findFilter(SecurityContextPersistenceFilter).repo == InvokeTwiceDoesNotOverrideConfig.SCR
	}

	@EnableWebSecurity
	static class InvokeTwiceDoesNotOverrideConfig extends WebSecurityConfigurerAdapter {
		static SecurityContextRepository SCR

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.securityContext()
					.securityContextRepository(SCR)
					.and()
				.securityContext()
		}
	}

	def 'SEC-2932: SecurityContextConfigurer defaults SecurityContextRepository'() {
		setup: 'Configuration without default SecurityContextRepository setup'
		loadConfig(SecurityContextRepositoryDefaultsSecurityContextRepositoryConfig)
		when: 'Spring Security invoked'
		springSecurityFilterChain.doFilter(request,response,chain)
		then: 'no exception thrown'
		noExceptionThrown()
	}

	@Configuration
	@EnableWebSecurity
	static class SecurityContextRepositoryDefaultsSecurityContextRepositoryConfig extends WebSecurityConfigurerAdapter {
		public SecurityContextRepositoryDefaultsSecurityContextRepositoryConfig() {
			super(true);
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.addFilter(new WebAsyncManagerIntegrationFilter())
				.anonymous().and()
				.securityContext().and()
				.authorizeRequests()
					.anyRequest().permitAll()
					.and()
				.httpBasic();
			// @formatter:on
		}

		// @formatter:off
		@Override
		protected void configure(AuthenticationManagerBuilder auth) {
			auth
			.inMemoryAuthentication()
			.withUser("user").password("password").roles("USER")
		}
		// @formatter:on
	}
}
