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
package org.springframework.security.config.annotation.web.configurers

import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.AnyObjectPostProcessor
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter

/**
 *
 * @author Rob Winch
 */
class HttpBasicConfigurerTests extends BaseSpringSpec {

    def "httBasic ObjectPostProcessor"() {
        setup:
            AnyObjectPostProcessor opp = Mock()
            HttpSecurity http = new HttpSecurity(opp, authenticationBldr, [:])
        when:
            http
                .httpBasic()
                    .and()
                .build()

        then: "ExceptionTranslationFilter is registered with LifecycleManager"
            1 * opp.postProcess(_ as BasicAuthenticationFilter) >> {BasicAuthenticationFilter o -> o}
    }

    def "SEC-2198: http.httpBasic() defaults AuthenticationEntryPoint"() {
        when:
            loadConfig(DefaultsEntryPointConfig)
        then:
            findFilter(ExceptionTranslationFilter).authenticationEntryPoint.class == BasicAuthenticationEntryPoint
    }

    @EnableWebSecurity
    @Configuration
    static class DefaultsEntryPointConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .httpBasic()
        }

        @Override
        protected void registerAuthentication(AuthenticationManagerBuilder auth)
                throws Exception {
            auth
                .inMemoryAuthentication()
        }
    }

    def "http.httpBasic().authenticationEntryPoint used for AuthenticationEntryPoint"() {
        setup:
            CustomAuthenticationEntryPointConfig.ENTRY_POINT = Mock(AuthenticationEntryPoint)
        when:
            loadConfig(CustomAuthenticationEntryPointConfig)
        then:
            findFilter(ExceptionTranslationFilter).authenticationEntryPoint == CustomAuthenticationEntryPointConfig.ENTRY_POINT
    }

    @EnableWebSecurity
    @Configuration
    static class CustomAuthenticationEntryPointConfig extends WebSecurityConfigurerAdapter {
        static AuthenticationEntryPoint ENTRY_POINT

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .httpBasic()
                    .authenticationEntryPoint(ENTRY_POINT)
        }

        @Override
        protected void registerAuthentication(AuthenticationManagerBuilder auth)
                throws Exception {
            auth
                .inMemoryAuthentication()
        }
    }
}
