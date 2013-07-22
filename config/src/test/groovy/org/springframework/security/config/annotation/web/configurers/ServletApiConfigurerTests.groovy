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

import groovy.transform.CompileStatic

import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.AnyObjectPostProcessor
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter

/**
 *
 * @author Rob Winch
 */
class ServletApiConfigurerTests extends BaseSpringSpec {

    def "servletApi ObjectPostProcessor"() {
        setup:
            AnyObjectPostProcessor opp = Mock()
            HttpSecurity http = new HttpSecurity(opp, authenticationBldr, [:])
        when:
            http
                .servletApi()
                    .and()
                .build()

        then: "SecurityContextHolderAwareRequestFilter is registered with LifecycleManager"
            1 * opp.postProcess(_ as SecurityContextHolderAwareRequestFilter) >> {SecurityContextHolderAwareRequestFilter o -> o}
    }

    def "SecurityContextHolderAwareRequestFilter properties set"() {
        when:
            loadConfig(ServletApiConfig)
            SecurityContextHolderAwareRequestFilter filter = findFilter(SecurityContextHolderAwareRequestFilter)
        then: "SEC-2215: authenticationManager != null"
            filter.authenticationManager != null
        and: "authenticationEntryPoint != null"
            filter.authenticationEntryPoint != null
        and: "requestFactory != null"
            filter.requestFactory != null
        and: "logoutHandlers populated"
            filter.logoutHandlers.collect { it.class } == [SecurityContextLogoutHandler]
    }

    @CompileStatic
    @EnableWebSecurity
    @Configuration
    static class ServletApiConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void registerAuthentication(AuthenticationManagerBuilder auth)
            throws Exception {
            auth
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER")
        }
    }

    def "SecurityContextHolderAwareRequestFilter.authenticationEntryPoint = customEntryPoint"() {
        setup:
            CustomEntryPointConfig.ENTRYPOINT = Mock(AuthenticationEntryPoint)
        when: "load config with customEntryPoint"
            loadConfig(CustomEntryPointConfig)
        then: "SecurityContextHolderAwareRequestFilter.authenticationEntryPoint == customEntryPoint"
            findFilter(SecurityContextHolderAwareRequestFilter).authenticationEntryPoint == CustomEntryPointConfig.ENTRYPOINT
    }

    @EnableWebSecurity
    @Configuration
    static class CustomEntryPointConfig extends WebSecurityConfigurerAdapter {
        static AuthenticationEntryPoint ENTRYPOINT

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .exceptionHandling()
                    .authenticationEntryPoint(ENTRYPOINT)
                    .and()
                .formLogin()
        }

        @Override
        protected void registerAuthentication(AuthenticationManagerBuilder auth)
            throws Exception {
            auth
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER")
        }
    }

    def "invoke servletApi twice does not override"() {
        setup:
            InvokeTwiceDoesNotOverrideConfig.ENTRYPOINT = Mock(AuthenticationEntryPoint)
        when:
            loadConfig(InvokeTwiceDoesNotOverrideConfig)
        then:
            findFilter(SecurityContextHolderAwareRequestFilter).authenticationEntryPoint == InvokeTwiceDoesNotOverrideConfig.ENTRYPOINT
    }

    @Configuration
    @EnableWebSecurity
    static class InvokeTwiceDoesNotOverrideConfig extends WebSecurityConfigurerAdapter {
        static AuthenticationEntryPoint ENTRYPOINT

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .exceptionHandling()
                    .authenticationEntryPoint(ENTRYPOINT)
                    .and()
                .exceptionHandling()
        }
    }
}
