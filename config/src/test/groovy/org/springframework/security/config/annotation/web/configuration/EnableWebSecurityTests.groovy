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
package org.springframework.security.config.annotation.web.configuration;

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.security.authentication.AnonymousAuthenticationToken
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.DebugFilter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter

class EnableWebSecurityTests extends BaseSpringSpec {

    def "@Bean(BeanIds.AUTHENTICATION_MANAGER) includes HttpSecurity's AuthenticationManagerBuilder"() {
        when:
            loadConfig(SecurityConfig)
            AuthenticationManager authenticationManager = context.getBean(AuthenticationManager)
            AnonymousAuthenticationToken anonymousAuthToken = findFilter(AnonymousAuthenticationFilter).createAuthentication(new MockHttpServletRequest())
        then:
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken("user", "password"))
            authenticationManager.authenticate(anonymousAuthToken)

    }


    @EnableWebSecurity
    @Configuration
    static class SecurityConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void registerAuthentication(AuthenticationManagerBuilder auth)
                throws Exception {
            auth
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER");
        }

        @Bean
        @Override
        public AuthenticationManager authenticationManagerBean()
                throws Exception {
            return super.authenticationManagerBean();
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .authorizeRequests()
                    .antMatchers("/*").hasRole("USER")
                    .and()
                .formLogin();
        }
    }

    def "@EnableWebSecurity on superclass"() {
        when:
            loadConfig(ChildSecurityConfig)
        then:
            context.getBean("springSecurityFilterChain", DebugFilter)
    }

    @Configuration
    static class ChildSecurityConfig extends DebugSecurityConfig {
    }

    @Configuration
    @EnableWebSecurity(debug=true)
    static class DebugSecurityConfig extends WebSecurityConfigurerAdapter {

    }
}
