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

import javax.servlet.http.HttpServletResponse

import org.springframework.context.annotation.Configuration
import org.springframework.http.MediaType
import org.springframework.security.config.annotation.AnyObjectPostProcessor
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.web.savedrequest.RequestCache
import org.springframework.security.web.savedrequest.RequestCacheAwareFilter

/**
 *
 * @author Rob Winch
 */
class RequestCacheConfigurerTests extends BaseSpringSpec {

    def "requestCache ObjectPostProcessor"() {
        setup:
            AnyObjectPostProcessor opp = Mock()
            HttpSecurity http = new HttpSecurity(opp, authenticationBldr, [:])
        when:
            http
                .requestCache()
                    .and()
                .build()

        then: "RequestCacheAwareFilter is registered with LifecycleManager"
            1 * opp.postProcess(_ as RequestCacheAwareFilter) >> {RequestCacheAwareFilter o -> o}
    }

    def "invoke requestCache twice does not reset"() {
        setup:
            RequestCache RC = Mock()
            AnyObjectPostProcessor opp = Mock()
            HttpSecurity http = new HttpSecurity(opp, authenticationBldr, [:])
        when:
            http
                .requestCache()
                    .requestCache(RC)
                    .and()
                .requestCache()

        then:
            http.getSharedObject(RequestCache) == RC
    }

    def "RequestCache disables faviocon.ico"() {
        setup:
            loadConfig(RequestCacheDefautlsConfig)
            request.servletPath = "/favicon.ico"
            request.requestURI = "/favicon.ico"
            request.method = "GET"
        when: "request favicon.ico"
            springSecurityFilterChain.doFilter(request,response,chain)
        then: "sent to the login page"
            response.status == HttpServletResponse.SC_MOVED_TEMPORARILY
            response.redirectedUrl == "http://localhost/login"
        when: "authenticate successfully"
            super.setupWeb(request.session)
            request.servletPath = "/login"
            request.setParameter("username","user")
            request.setParameter("password","password")
            request.method = "POST"
            springSecurityFilterChain.doFilter(request,response,chain)
        then: "sent to default URL since it was favicon.ico"
            response.status == HttpServletResponse.SC_MOVED_TEMPORARILY
            response.redirectedUrl == "/"
    }

    @Configuration
    @EnableWebSecurity
    static class RequestCacheDefautlsConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .authorizeRequests()
                    .anyRequest().authenticated()
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
}
