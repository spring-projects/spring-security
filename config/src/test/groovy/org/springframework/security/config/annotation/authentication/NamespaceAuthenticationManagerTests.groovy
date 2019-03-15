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
package org.springframework.security.config.annotation.authentication

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication

/**
 *
 * @author Rob Winch
 *
 */
class NamespaceAuthenticationManagerTests extends BaseSpringSpec {
	def "authentication-manager@erase-credentials=true (default)"() {
		when:
			loadConfig(EraseCredentialsTrueDefaultConfig)
			Authentication auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken("user","password"))
		then:
			auth.principal.password == null
			auth.credentials == null
		when: "authenticate the same user"
			auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken("user","password"))
		then: "successfully authenticate again"
			noExceptionThrown()
	}

	@EnableWebSecurity
	static class EraseCredentialsTrueDefaultConfig extends WebSecurityConfigurerAdapter {
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
				.inMemoryAuthentication()
					.withUser("user").password("password").roles("USER")
		}

		// Only necessary to have access to verify the AuthenticationManager
		@Bean
		@Override
		public AuthenticationManager authenticationManagerBean()
				throws Exception {
			return super.authenticationManagerBean();
		}
	}

	def "authentication-manager@erase-credentials=false"() {
		when:
			loadConfig(EraseCredentialsFalseConfig)
			Authentication auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken("user","password"))
		then:
			auth.credentials == "password"
			auth.principal.password == "password"
	}

	@EnableWebSecurity
	static class EraseCredentialsFalseConfig extends WebSecurityConfigurerAdapter {
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
				.eraseCredentials(false)
				.inMemoryAuthentication()
					.withUser("user").password("password").roles("USER")
		}

		// Only necessary to have access to verify the AuthenticationManager
		@Bean
		@Override
		public AuthenticationManager authenticationManagerBean()
				throws Exception {
			return super.authenticationManagerBean();
		}
	}

	def "SEC-2533: global authentication-manager@erase-credentials=false"() {
		when:
			loadConfig(GlobalEraseCredentialsFalseConfig)
			Authentication auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken("user","password"))
		then:
			auth.credentials == "password"
			auth.principal.password == "password"
	}

	@EnableWebSecurity
	static class GlobalEraseCredentialsFalseConfig extends WebSecurityConfigurerAdapter {
		@Autowired
		public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
			auth
				.eraseCredentials(false)
				.inMemoryAuthentication()
					.withUser("user").password("password").roles("USER")
		}
	}
}
