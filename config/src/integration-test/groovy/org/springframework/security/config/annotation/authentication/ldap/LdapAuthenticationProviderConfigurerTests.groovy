/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.config.annotation.authentication.ldap

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.core.authority.SimpleGrantedAuthority

/**
 *
 * @author Rob Winch
 * @author Eddú Meléndez
 *
 */
class LdapAuthenticationProviderConfigurerTests extends BaseSpringSpec {

	def "authentication-manager support multiple default ldap contexts (ports dynamically allocated)"() {
		when:
			loadConfig(MultiLdapAuthenticationProvidersConfig)
		then:
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken("bob","bobspassword"))
	}

	def "authentication-manager support multiple ldap context with default role prefix" () {
		when:
		loadConfig(MultiLdapAuthenticationProvidersConfig)
		then:
		def authenticate = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken("bob", "bobspassword"))
		authenticate.authorities.contains(new SimpleGrantedAuthority("ROLE_DEVELOPERS"))
	}

	def "authentication-manager support multiple ldap context with custom role prefix"() {
		when:
		loadConfig(MultiLdapWithCustomRolePrefixAuthenticationProvidersConfig)
		then:
		def authenticate = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken("bob", "bobspassword"))
		authenticate.authorities.contains(new SimpleGrantedAuthority("ROL_DEVELOPERS"))
	}

	@EnableWebSecurity
	static class MultiLdapAuthenticationProvidersConfig extends WebSecurityConfigurerAdapter {
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
				.ldapAuthentication()
					.groupSearchBase("ou=groups")
					.groupSearchFilter("(member={0})")
					.userDnPatterns("uid={0},ou=people")
					.and()
				.ldapAuthentication()
					.groupSearchBase("ou=groups")
					.groupSearchFilter("(member={0})")
					.userDnPatterns("uid={0},ou=people")
		}
	}

	@EnableWebSecurity
	static class MultiLdapWithCustomRolePrefixAuthenticationProvidersConfig extends
			WebSecurityConfigurerAdapter {
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
				.ldapAuthentication()
					.groupSearchBase("ou=groups")
					.groupSearchFilter("(member={0})")
					.userDnPatterns("uid={0},ou=people")
					.rolePrefix("ROL_")
					.and()
				.ldapAuthentication()
					.groupSearchBase("ou=groups")
					.groupSearchFilter("(member={0})")
					.userDnPatterns("uid={0},ou=people")
					.rolePrefix("RUOLO_")
		}
	}
}
