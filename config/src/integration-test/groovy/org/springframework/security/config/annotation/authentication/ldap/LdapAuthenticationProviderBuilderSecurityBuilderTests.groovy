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

import org.springframework.beans.factory.config.AutowireCapableBeanFactory
import org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Import
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.authentication.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication
import org.springframework.security.config.annotation.configuration.AutowireBeanFactoryObjectPostProcessor
import org.springframework.security.config.annotation.configuration.AutowireBeanFactoryObjectPostProcessorTests
import org.springframework.security.config.annotation.configuration.ObjectPostProcessorConfiguration
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.server.ApacheDSContainer;
import org.springframework.test.util.ReflectionTestUtils;

/**
 *
 * @author Rob Winch
 *
 */
class LdapAuthenticationProviderBuilderSecurityBuilderTests extends BaseSpringSpec {
    def "default configuration"() {
        when:
        loadConfig(DefaultLdapConfig)
        LdapAuthenticationProvider provider = ldapProvider()
        then:
        provider.authoritiesPopulator.groupRoleAttribute == "cn"
        provider.authoritiesPopulator.groupSearchBase == ""
        provider.authoritiesPopulator.groupSearchFilter == "(uniqueMember={0})"
        ReflectionTestUtils.getField(provider,"authoritiesMapper").prefix == "ROLE_"

    }

    @Configuration
    static class DefaultLdapConfig extends BaseLdapProviderConfig {
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                .ldapAuthentication()
                    .contextSource(contextSource())
                    .userDnPatterns("uid={0},ou=people")
        }
    }

    def "group roles custom"() {
        when:
        loadConfig(GroupRolesConfig)
        LdapAuthenticationProvider provider = ldapProvider()
        then:
        provider.authoritiesPopulator.groupRoleAttribute == "group"
    }

    @Configuration
    static class GroupRolesConfig extends BaseLdapProviderConfig {
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                .ldapAuthentication()
                    .contextSource(contextSource())
                    .userDnPatterns("uid={0},ou=people")
                    .groupRoleAttribute("group")
        }
    }

    def "group search custom"() {
        when:
        loadConfig(GroupSearchConfig)
        LdapAuthenticationProvider provider = ldapProvider()
        then:
        provider.authoritiesPopulator.groupSearchFilter == "ou=groupName"
    }

    @Configuration
    static class GroupSearchConfig extends BaseLdapProviderConfig {
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                .ldapAuthentication()
                    .contextSource(contextSource())
                    .userDnPatterns("uid={0},ou=people")
                    .groupSearchFilter("ou=groupName");
        }
    }

    def "role prefix custom"() {
        when:
        loadConfig(RolePrefixConfig)
        LdapAuthenticationProvider provider = ldapProvider()
        then:
        ReflectionTestUtils.getField(provider,"authoritiesMapper").prefix == "role_"
    }

    @Configuration
    static class RolePrefixConfig extends BaseLdapProviderConfig {
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                .ldapAuthentication()
                    .contextSource(contextSource())
                    .userDnPatterns("uid={0},ou=people")
                    .rolePrefix("role_")
        }
    }

    def "bind authentication"() {
        when:
        loadConfig(BindAuthenticationConfig)
        AuthenticationManager auth = context.getBean(AuthenticationManager)
        then:
        auth
        auth.authenticate(new UsernamePasswordAuthenticationToken("bob","bobspassword")).authorities.collect { it.authority }.sort() == ["ROLE_DEVELOPERS"]
    }

    @Configuration
    static class BindAuthenticationConfig extends BaseLdapServerConfig {
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                .ldapAuthentication()
                    .contextSource(contextSource())
                    .groupSearchBase("ou=groups")
                    .groupSearchFilter("(member={0})")
                    .userDnPatterns("uid={0},ou=people");
        }
    }

    def "SEC-2472: Can use crypto PasswordEncoder"() {
        setup:
        loadConfig(PasswordEncoderConfig)
        when:
        AuthenticationManager auth = context.getBean(AuthenticationManager)
        then:
        auth.authenticate(new UsernamePasswordAuthenticationToken("bcrypt","password")).authorities.collect { it.authority }.sort() == ["ROLE_DEVELOPERS"]
    }

    @Configuration
    static class PasswordEncoderConfig extends BaseLdapServerConfig {
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                .ldapAuthentication()
                    .contextSource(contextSource())
                    .passwordEncoder(new BCryptPasswordEncoder())
                    .groupSearchBase("ou=groups")
                    .groupSearchFilter("(member={0})")
                    .userDnPatterns("uid={0},ou=people");
        }
    }

    def ldapProvider() {
        context.getBean(AuthenticationManager).providers[0]
    }

    @Configuration
    static abstract class BaseLdapServerConfig extends BaseLdapProviderConfig {
        @Bean
        public ApacheDSContainer ldapServer() throws Exception {
            ApacheDSContainer apacheDSContainer = new ApacheDSContainer("dc=springframework,dc=org", "classpath:/test-server.ldif");
            apacheDSContainer.setPort(getPort());
            return apacheDSContainer;
        }
    }

    @Configuration
    @EnableGlobalAuthentication
    @Import(ObjectPostProcessorConfiguration)
    static abstract class BaseLdapProviderConfig {

        @Bean
        public BaseLdapPathContextSource contextSource() throws Exception {
            DefaultSpringSecurityContextSource contextSource = new DefaultSpringSecurityContextSource(
                    "ldap://127.0.0.1:"+ getPort() + "/dc=springframework,dc=org")
            contextSource.userDn = "uid=admin,ou=system"
            contextSource.password = "secret"
            contextSource.afterPropertiesSet()
            return contextSource;
        }

        @Bean
        public AuthenticationManager authenticationManager(AuthenticationManagerBuilder auth) {
            configure(auth)
            auth.build()
        }

        abstract protected void configure(AuthenticationManagerBuilder auth)
    }

    static Integer port;

    static int getPort() {
        if(port == null) {
            ServerSocket socket = new ServerSocket(0)
            port = socket.localPort
            socket.close()
        }
        port
    }
}
