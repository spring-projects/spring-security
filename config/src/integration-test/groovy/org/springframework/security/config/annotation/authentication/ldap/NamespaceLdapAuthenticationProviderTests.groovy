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
package org.springframework.security.config.annotation.authentication.ldap

import static org.springframework.security.config.annotation.authentication.ldap.NamespaceLdapAuthenticationProviderTestsConfigs.*

import org.springframework.ldap.core.support.BaseLdapPathContextSource
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.ldap.NamespaceLdapAuthenticationProviderTestsConfigs.LdapAuthenticationProviderConfig;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.authentication.PasswordComparisonAuthenticator;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.PersonContextMapper;
import org.springframework.test.util.ReflectionTestUtils;

/**
 *
 * @author Rob Winch
 *
 */
class NamespaceLdapAuthenticationProviderTests extends BaseSpringSpec {
	def "ldap-authentication-provider"() {
		when:
			loadConfig(LdapAuthenticationProviderConfig)
		then:
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken("bob","bobspassword"))
	}

	def "ldap-authentication-provider custom"() {
		when:
			loadConfig(CustomLdapAuthenticationProviderConfig)
			LdapAuthenticationProvider provider = findAuthenticationProvider(LdapAuthenticationProvider)
		then:
			provider.authoritiesPopulator.groupRoleAttribute == "cn"
			provider.authoritiesPopulator.groupSearchBase == "ou=groups"
			provider.authoritiesPopulator.groupSearchFilter == "(member={0})"
			ReflectionTestUtils.getField(provider,"authoritiesMapper").prefix == "PREFIX_"
			provider.userDetailsContextMapper instanceof PersonContextMapper
			provider.authenticator.getUserDns("user") == ["uid=user,ou=people"]
			provider.authenticator.userSearch.searchBase == "ou=users"
			provider.authenticator.userSearch.searchFilter == "(uid={0})"
	}

	def "SEC-2490: ldap-authentication-provider custom LdapAuthoritiesPopulator"() {
		setup:
			LdapAuthoritiesPopulator LAP = Mock()
			CustomAuthoritiesPopulatorConfig.LAP = LAP
		when:
			loadConfig(CustomAuthoritiesPopulatorConfig)
			LdapAuthenticationProvider provider = findAuthenticationProvider(LdapAuthenticationProvider)
		then:
			provider.authoritiesPopulator == LAP
	}

	def "ldap-authentication-provider password compare"() {
		when:
			loadConfig(PasswordCompareLdapConfig)
			LdapAuthenticationProvider provider = findAuthenticationProvider(LdapAuthenticationProvider)
		then:
			provider.authenticator instanceof PasswordComparisonAuthenticator
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken("bob","bobspassword"))
	}
}
