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

import static org.springframework.security.config.annotation.authentication.PasswordEncoderConfigurerConfigs.*

import javax.sql.DataSource

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.configurers.ldap.LdapAuthenticationProviderConfigurer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.userdetails.User
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.provisioning.InMemoryUserDetailsManager

/**
 *
 * @author Rob Winch
 *
 */
class NamespacePasswordEncoderTests extends BaseSpringSpec {
    def "password-encoder@ref with in memory"() {
        when:
            loadConfig(PasswordEncoderWithInMemoryConfig)
        then:
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken("user", "password"))
    }

    @EnableWebSecurity
    @Configuration
    static class PasswordEncoderWithInMemoryConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {

            BCryptPasswordEncoder encoder = new BCryptPasswordEncoder()
            auth
                .inMemoryAuthentication()
                    .withUser("user").password(encoder.encode("password")).roles("USER").and()
                    .passwordEncoder(encoder)
        }
    }

    def "password-encoder@ref with jdbc"() {
        when:
            loadConfig(PasswordEncoderWithJdbcConfig)
        then:
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken("user", "password"))
    }

    @EnableWebSecurity
    @Configuration
    static class PasswordEncoderWithJdbcConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {

            BCryptPasswordEncoder encoder = new BCryptPasswordEncoder()
            auth
                .jdbcAuthentication()
                    .withDefaultSchema()
                    .dataSource(dataSource())
                    .withUser("user").password(encoder.encode("password")).roles("USER").and()
                    .passwordEncoder(encoder)
        }

        @Bean
        public DataSource dataSource() {
            EmbeddedDatabaseBuilder builder = new EmbeddedDatabaseBuilder()
            return builder.setType(EmbeddedDatabaseType.HSQL).build();
        }
    }

    def "password-encoder@ref with userdetailsservice"() {
        when:
            loadConfig(PasswordEncoderWithUserDetailsServiceConfig)
        then:
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken("user", "password"))
    }

    @EnableWebSecurity
    @Configuration
    static class PasswordEncoderWithUserDetailsServiceConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {

            BCryptPasswordEncoder encoder = new BCryptPasswordEncoder()
            User user = new User("user",encoder.encode("password"), AuthorityUtils.createAuthorityList("ROLE_USER"))
            InMemoryUserDetailsManager uds = new InMemoryUserDetailsManager([user])
            auth
                .userDetailsService(uds)
                    .passwordEncoder(encoder)
        }

        @Bean
        public DataSource dataSource() {
            EmbeddedDatabaseBuilder builder = new EmbeddedDatabaseBuilder()
            return builder.setType(EmbeddedDatabaseType.HSQL).build();
        }
    }
}
