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
package org.springframework.security.config.annotation.web.configurers.openid

import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.AnyObjectPostProcessor
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.openid.OpenIDAuthenticationFilter
import org.springframework.security.openid.OpenIDAuthenticationProvider
import org.springframework.security.openid.OpenIDAuthenticationToken

/**
 *
 * @author Rob Winch
 */
class OpenIDLoginConfigurerTests extends BaseSpringSpec {

	def "openidLogin ObjectPostProcessor"() {
		setup:
			AnyObjectPostProcessor opp = Mock()
			HttpSecurity http = new HttpSecurity(opp, authenticationBldr, [:])
			UserDetailsService uds = authenticationBldr.getDefaultUserDetailsService()
		when:
			http
				.openidLogin()
					.authenticationUserDetailsService(new UserDetailsByNameServiceWrapper<OpenIDAuthenticationToken>(uds))
					.and()
				.build()

		then: "OpenIDAuthenticationFilter is registered with LifecycleManager"
			1 * opp.postProcess(_ as OpenIDAuthenticationFilter) >> {OpenIDAuthenticationFilter o -> o}
		and: "OpenIDAuthenticationProvider is registered with LifecycleManager"
			1 * opp.postProcess(_ as OpenIDAuthenticationProvider) >> {OpenIDAuthenticationProvider o -> o}
	}

	def "invoke openidLogin twice does not override"() {
		setup:
			loadConfig(InvokeTwiceDoesNotOverrideConfig)
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			response.redirectedUrl.endsWith("/login/custom")

	}

	@EnableWebSecurity
	static class InvokeTwiceDoesNotOverrideConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
				.inMemoryAuthentication()
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.openidLogin()
					.loginPage("/login/custom")
					.and()
				.openidLogin()
		}
	}
}
