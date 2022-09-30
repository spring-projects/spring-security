/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.config.annotation.authentication.ldap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.PersonContextMapper;

/**
 * @author Rob Winch
 *
 */
public class NamespaceLdapAuthenticationProviderTestsConfigs {

	@Configuration
	@EnableWebSecurity
	static class LdapAuthenticationProviderConfig {

		@Autowired
		void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.ldapAuthentication()
					.groupSearchBase("ou=groups")
					.userDnPatterns("uid={0},ou=people"); // ldap-server@user-dn-pattern
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CustomLdapAuthenticationProviderConfig {

		@Autowired
		void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.ldapAuthentication()
					.groupRoleAttribute("cn") // ldap-authentication-provider@group-role-attribute
					.groupSearchBase("ou=groups") // ldap-authentication-provider@group-search-base
					.groupSearchFilter("(member={0})") // ldap-authentication-provider@group-search-filter
					.rolePrefix("PREFIX_") // ldap-authentication-provider@group-search-filter
					.userDetailsContextMapper(new PersonContextMapper()) // ldap-authentication-provider@user-context-mapper-ref / ldap-authentication-provider@user-details-class
					.userDnPatterns("uid={0},ou=people") // ldap-authentication-provider@user-dn-pattern
					.userSearchBase("ou=users") // ldap-authentication-provider@user-dn-pattern
					.userSearchFilter("(uid={0})") // ldap-authentication-provider@user-search-filter
					// .contextSource(contextSource) // ldap-authentication-provider@server-ref
					.contextSource()
						.ldif("classpath:users.xldif") // ldap-server@ldif
						.managerDn("uid=admin,ou=system") // ldap-server@manager-dn
						.managerPassword("secret") // ldap-server@manager-password
						.port(0) // ldap-server@port
						.root("dc=springframework,dc=org"); // ldap-server@root
			// .url("ldap://localhost:33389/dc-springframework,dc=org") this overrides root and port and is used for external
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CustomAuthoritiesPopulatorConfig {

		static LdapAuthoritiesPopulator LAP;

		@Autowired
		void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.ldapAuthentication()
					.userSearchFilter("(uid={0})")
					.ldapAuthoritiesPopulator(LAP);
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class PasswordCompareLdapConfig {

		@Autowired
		void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.ldapAuthentication()
					.groupSearchBase("ou=groups")
					.userSearchFilter("(uid={0})")
					.passwordCompare()
						.passwordEncoder(new BCryptPasswordEncoder()) // ldap-authentication-provider/password-compare/password-encoder@ref
						.passwordAttribute("userPassword"); // ldap-authentication-provider/password-compare@password-attribute
			// @formatter:on
		}

	}

}
