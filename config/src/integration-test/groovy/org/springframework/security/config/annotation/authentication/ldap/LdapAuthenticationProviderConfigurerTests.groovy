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

import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.authentication.ldap.NamespaceLdapAuthenticationProviderTestsConfigs.LdapAuthenticationProviderConfig
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider
import org.springframework.security.ldap.authentication.PasswordComparisonAuthenticator
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator
import org.springframework.security.ldap.userdetails.PersonContextMapper
import org.springframework.test.util.ReflectionTestUtils

import static org.springframework.security.config.annotation.authentication.ldap.NamespaceLdapAuthenticationProviderTestsConfigs.*

/**
 *
 * @author Rob Winch
 *
 */
class LdapAuthenticationProviderConfigurerTests extends BaseSpringSpec {

    def "authentication-manager support multiple default ldap contexts (ports dynamically allocated)"() {
        when:
            loadConfig(MultiLdapAuthenticationProvidersConfig)
        then:
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken("bob","bobspassword"))
    }

    @EnableWebSecurity
    @Configuration
    static class MultiLdapAuthenticationProvidersConfig extends WebSecurityConfigurerAdapter {
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                .ldapAuthentication()
                    .groupSearchBase("ou=groups")
                    .userDnPatterns("uid={0},ou=people")
                    .and()
                .ldapAuthentication()
                    .groupSearchBase("ou=groups")
                    .userDnPatterns("uid={0},ou=people")
        }
    }
}
