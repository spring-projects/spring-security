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
package org.springframework.security.config.annotation.web.configurers;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.config.annotation.BaseSpringSpec;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.BaseWebConfig;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

/**
 * Tests to verify that all the functionality of <http-basic> attributes is present
 *
 * @author Rob Winch
 *
 */
public class NamespaceHttpBasicTests extends BaseSpringSpec {

    def "http/http-basic"() {
        setup:
            loadConfig(HttpBasicConfig)
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.status == HttpServletResponse.SC_UNAUTHORIZED
        when: "fail to log in"
            super.setup()
            basicLogin("user","invalid")
            springSecurityFilterChain.doFilter(request,response,chain)
        then: "unauthorized"
            response.status == HttpServletResponse.SC_UNAUTHORIZED
            response.getHeader("WWW-Authenticate") == 'Basic realm="Realm"'
        when: "login success"
            super.setup()
            basicLogin()
        then: "sent to default succes page"
            !response.committed
    }

    @Configuration
    static class HttpBasicConfig extends BaseWebConfig {
        protected void configure(HttpSecurity http) {
            http
                .authorizeRequests()
                    .anyRequest().hasRole("USER")
                    .and()
                .httpBasic();
        }
    }

    def "http@realm"() {
        setup:
            loadConfig(CustomHttpBasicConfig)
        when:
            basicLogin("user","invalid")
            springSecurityFilterChain.doFilter(request,response,chain)
        then: "unauthorized"
            response.status == HttpServletResponse.SC_UNAUTHORIZED
            response.getHeader("WWW-Authenticate") == 'Basic realm="Custom Realm"'
    }

    @Configuration
    static class CustomHttpBasicConfig extends BaseWebConfig {
        protected void configure(HttpSecurity http) {
            http
                .authorizeRequests()
                    .anyRequest().hasRole("USER")
                    .and()
                .httpBasic().realmName("Custom Realm");
        }
    }

    def "http-basic@authentication-details-source-ref"() {
        when:
            loadConfig(AuthenticationDetailsSourceHttpBasicConfig)
        then:
            findFilter(BasicAuthenticationFilter).authenticationDetailsSource.class == CustomAuthenticationDetailsSource
    }

    @Configuration
    static class AuthenticationDetailsSourceHttpBasicConfig extends BaseWebConfig {
        protected void configure(HttpSecurity http) {
            http
                .httpBasic()
                    .authenticationDetailsSource(new CustomAuthenticationDetailsSource())
        }
    }

    static class CustomAuthenticationDetailsSource extends WebAuthenticationDetailsSource {}

    def "http-basic@entry-point-ref"() {
        setup:
            loadConfig(EntryPointRefHttpBasicConfig)
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.status == HttpServletResponse.SC_INTERNAL_SERVER_ERROR
        when: "fail to log in"
            super.setup()
            basicLogin("user","invalid")
            springSecurityFilterChain.doFilter(request,response,chain)
        then: "custom"
            response.status == HttpServletResponse.SC_INTERNAL_SERVER_ERROR
        when: "login success"
            super.setup()
            basicLogin()
            springSecurityFilterChain.doFilter(request,response,chain)
        then: "sent to default succes page"
            !response.committed
    }

    @Configuration
    static class EntryPointRefHttpBasicConfig extends BaseWebConfig {
        protected void configure(HttpSecurity http) {
            http
                .authorizeRequests()
                    .anyRequest().hasRole("USER")
                    .and()
                .httpBasic()
                    .authenticationEntryPoint(new AuthenticationEntryPoint() {
                        public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) {
                            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR)
                        }
                    })
        }
    }

    def basicLogin(String username="user",String password="password") {
        def credentials = username + ":" + password
        request.addHeader("Authorization", "Basic " + credentials.bytes.encodeBase64())
    }
}
