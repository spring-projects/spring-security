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

import javax.sql.DataSource

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.NamespaceJdbcUserServiceTests.CustomJdbcUserServiceSampleConfig.CustomUserCache;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.UserCache
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.JdbcUserDetailsManager

/**
 *
 * @author Rob Winch
 *
 */
class NamespaceJdbcUserServiceTests extends BaseSpringSpec {
    def "jdbc-user-service"() {
        when:
            loadConfig(DataSourceConfig,JdbcUserServiceConfig)
        then:
            findAuthenticationProvider(DaoAuthenticationProvider).userDetailsService instanceof JdbcUserDetailsManager
    }

    @EnableWebSecurity
    @Configuration
    static class JdbcUserServiceConfig extends WebSecurityConfigurerAdapter {
        @Autowired
        private DataSource dataSource;

        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                .jdbcAuthentication()
                    .dataSource(dataSource) // jdbc-user-service@data-source-ref
        }

        // Only necessary to have access to verify the AuthenticationManager
        @Bean
        @Override
        public AuthenticationManager authenticationManagerBean()
                throws Exception {
            return super.authenticationManagerBean();
        }
    }

    def "jdbc-user-service in memory testing sample"() {
        when:
            loadConfig(DataSourceConfig,JdbcUserServiceInMemorySampleConfig)
        then:
           Authentication auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken("user", "password"))
            auth.authorities.collect {it.authority} == ['ROLE_USER']
            auth.name == "user"
    }

    @EnableWebSecurity
    @Configuration
    static class JdbcUserServiceInMemorySampleConfig extends WebSecurityConfigurerAdapter {
        @Autowired
        private DataSource dataSource;

        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                .jdbcAuthentication()
                    .dataSource(dataSource)
                    // imports the default schema (will fail if already exists)
                    .withDefaultSchema()
                    // adds this user automatically (will fail if already exists)
                    .withUser("user")
                        .password("password")
                        .roles("USER")
        }

        // Only necessary to have access to verify the AuthenticationManager
        @Bean
        @Override
        public AuthenticationManager authenticationManagerBean()
                throws Exception {
            return super.authenticationManagerBean();
        }
    }

    @Configuration
    static class DataSourceConfig {
        @Bean
        public DataSource dataSource() {
            EmbeddedDatabaseBuilder builder = new EmbeddedDatabaseBuilder()
            return builder.setType(EmbeddedDatabaseType.HSQL).build();
        }
    }

    def "jdbc-user-service custom"() {
        when:
            loadConfig(CustomDataSourceConfig,CustomJdbcUserServiceSampleConfig)
        then:
            findAuthenticationProvider(DaoAuthenticationProvider).userDetailsService.userCache instanceof CustomUserCache
        when:
            Authentication auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken("user", "password"))
        then:
            auth.authorities.collect {it.authority}.sort() == ['ROLE_DBA','ROLE_USER']
            auth.name == 'user'
    }

    @EnableWebSecurity
    @Configuration
    static class CustomJdbcUserServiceSampleConfig extends WebSecurityConfigurerAdapter {
        @Autowired
        private DataSource dataSource;

        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                .jdbcAuthentication()
                    // jdbc-user-service@dataSource
                    .dataSource(dataSource)
                    // jdbc-user-service@cache-ref
                    .userCache(new CustomUserCache())
                    // jdbc-user-service@users-byusername-query
                    .usersByUsernameQuery("select principal,credentials,true from users where principal = ?")
                    // jdbc-user-service@authorities-by-username-query
                    .authoritiesByUsernameQuery("select principal,role from roles where principal = ?")
                    // jdbc-user-service@group-authorities-by-username-query
                    .groupAuthoritiesByUsername(JdbcUserDetailsManager.DEF_GROUP_AUTHORITIES_BY_USERNAME_QUERY)
                    // jdbc-user-service@role-prefix
                    .rolePrefix("ROLE_")

        }

        // Only necessary to have access to verify the AuthenticationManager
        @Bean
        @Override
        public AuthenticationManager authenticationManagerBean()
                throws Exception {
            return super.authenticationManagerBean();
        }

        static class CustomUserCache implements UserCache {

            @Override
            public UserDetails getUserFromCache(String username) {
                return null;
            }

            @Override
            public void putUserInCache(UserDetails user) {
            }

            @Override
            public void removeUserFromCache(String username) {
            }
        }
    }

    @Configuration
    static class CustomDataSourceConfig {
        @Bean
        public DataSource dataSource() {
            EmbeddedDatabaseBuilder builder = new EmbeddedDatabaseBuilder()
                // simulate that the DB already has the schema loaded and users in it
                .addScript("CustomJdbcUserServiceSampleConfig.sql")
            return builder.setType(EmbeddedDatabaseType.HSQL).build();
        }
    }
}
