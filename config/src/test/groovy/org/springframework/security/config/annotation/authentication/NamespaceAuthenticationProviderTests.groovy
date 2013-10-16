/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation.authentication

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.provisioning.InMemoryUserDetailsManager

/**
 *
 * @author Rob Winch
 *
 */
class NamespaceAuthenticationProviderTests extends BaseSpringSpec {
    def "authentication-provider@ref"() {
        when:
            loadConfig(AuthenticationProviderRefConfig)
        then:
            authenticationProviders()[1] == AuthenticationProviderRefConfig.expected
    }

    @EnableWebSecurity
    @Configuration
    static class AuthenticationProviderRefConfig extends WebSecurityConfigurerAdapter {
        static DaoAuthenticationProvider expected = new DaoAuthenticationProvider()
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                .authenticationProvider(expected)
        }

        // Only necessary to have access to verify the AuthenticationManager
        @Bean
        @Override
        public AuthenticationManager authenticationManagerBean()
                throws Exception {
            return super.authenticationManagerBean();
        }
    }

    def "authentication-provider@user-service-ref"() {
        when:
            loadConfig(UserServiceRefConfig)
        then:
            findAuthenticationProvider(DaoAuthenticationProvider).userDetailsService == UserServiceRefConfig.expected
    }

    @EnableWebSecurity
    @Configuration
    static class UserServiceRefConfig extends WebSecurityConfigurerAdapter {
        static InMemoryUserDetailsManager expected = new InMemoryUserDetailsManager([] as Collection)
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                .userDetailsService(expected)
        }

        // Only necessary to have access to verify the AuthenticationManager
        @Bean
        @Override
        public AuthenticationManager authenticationManagerBean()
                throws Exception {
            return super.authenticationManagerBean();
        }
    }
}
