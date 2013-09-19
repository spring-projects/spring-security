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
import org.springframework.security.web.authentication.logout.LogoutFilter

/**
 *
 * @author Rob Winch
 */
class LogoutConfigurerTests extends BaseSpringSpec {

    def "logout ObjectPostProcessor"() {
        setup:
            AnyObjectPostProcessor opp = Mock()
            HttpSecurity http = new HttpSecurity(opp, authenticationBldr, [:])
        when:
            http
                .logout()
                    .and()
                .build()

        then: "LogoutFilter is registered with LifecycleManager"
            1 * opp.postProcess(_ as LogoutFilter) >> {LogoutFilter o -> o}
    }

    def "invoke logout twice does not override"() {
        when:
            loadConfig(InvokeTwiceDoesNotOverride)
            request.method = "POST"
            request.servletPath = "/custom/logout"
            findFilter(LogoutFilter).doFilter(request,response,chain)
        then:
            response.redirectedUrl == "/login?logout"
    }

    @Configuration
    @EnableWebSecurity
    static class InvokeTwiceDoesNotOverride extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .logout()
                    .logoutUrl("/custom/logout")
                    .and()
                .logout()
        }
    }

    def "SEC-2311: Logout allows other methods if CSRF is disabled"() {
        when:
            loadConfig(CsrfDisabledConfig)
            request.method = "GET"
            request.servletPath = "/logout"
            findFilter(LogoutFilter).doFilter(request,response,chain)
        then:
            response.redirectedUrl == "/login?logout"
    }

    @Configuration
    @EnableWebSecurity
    static class CsrfDisabledConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .csrf().disable()
                .logout()
        }
    }


    def "SEC-2311: Logout allows other methods if CSRF is disabled with custom logout URL"() {
        when:
            loadConfig(CsrfDisabledCustomLogoutUrlConfig)
            request.method = "GET"
            request.servletPath = "/custom/logout"
            findFilter(LogoutFilter).doFilter(request,response,chain)
        then:
            response.redirectedUrl == "/login?logout"
    }

    @Configuration
    @EnableWebSecurity
    static class CsrfDisabledCustomLogoutUrlConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .logout()
                    .logoutUrl("/custom/logout")
                    .and()
                .csrf().disable()
        }
    }
}
