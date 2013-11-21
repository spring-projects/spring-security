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
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.web.access.AccessDeniedHandler
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.servlet.support.csrf.CsrfRequestDataValueProcessor;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.servlet.support.RequestDataValueProcessor;

import spock.lang.Unroll;

/**
 *
 * @author Rob Winch
 */
class CsrfConfigurerTests extends BaseSpringSpec {

    @Unroll
    def "csrf applied by default"() {
        setup:
            loadConfig(CsrfAppliedDefaultConfig)
            request.method = httpMethod
            clearCsrfToken()
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.status == httpStatus
        where:
            httpMethod | httpStatus
            'POST'     | HttpServletResponse.SC_FORBIDDEN
            'PUT'      | HttpServletResponse.SC_FORBIDDEN
            'PATCH'    | HttpServletResponse.SC_FORBIDDEN
            'DELETE'   | HttpServletResponse.SC_FORBIDDEN
            'INVALID'  | HttpServletResponse.SC_FORBIDDEN
            'GET'      | HttpServletResponse.SC_OK
            'HEAD'     | HttpServletResponse.SC_OK
            'TRACE'    | HttpServletResponse.SC_OK
            'OPTIONS'  | HttpServletResponse.SC_OK
    }

    def "csrf default creates CsrfRequestDataValueProcessor"() {
        when:
            loadConfig(CsrfAppliedDefaultConfig)
        then:
            context.getBean(RequestDataValueProcessor)
    }

    @Configuration
    @EnableWebSecurity
    static class CsrfAppliedDefaultConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
        }
    }

    def "csrf disable"() {
        setup:
            loadConfig(DisableCsrfConfig)
            request.method = "POST"
            clearCsrfToken()
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            !findFilter(CsrfFilter)
            response.status == HttpServletResponse.SC_OK
    }

    @Configuration
    @EnableWebSecurity
    static class DisableCsrfConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .csrf().disable()
        }
    }

    def "csrf requireCsrfProtectionMatcher"() {
        setup:
            RequireCsrfProtectionMatcherConfig.matcher = Mock(RequestMatcher)
            RequireCsrfProtectionMatcherConfig.matcher.matches(_) >>> [false,true]
            loadConfig(RequireCsrfProtectionMatcherConfig)
            clearCsrfToken()
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.status == HttpServletResponse.SC_OK
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.status == HttpServletResponse.SC_FORBIDDEN
    }

    @Configuration
    @EnableWebSecurity
    static class RequireCsrfProtectionMatcherConfig extends WebSecurityConfigurerAdapter {
        static RequestMatcher matcher

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .csrf()
                    .requireCsrfProtectionMatcher(matcher)
        }
    }

    def "csrf csrfTokenRepository"() {
        setup:
            CsrfTokenRepositoryConfig.repo = Mock(CsrfTokenRepository)
            loadConfig(CsrfTokenRepositoryConfig)
            clearCsrfToken()
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            1 * CsrfTokenRepositoryConfig.repo.loadToken(_) >> csrfToken
            response.status == HttpServletResponse.SC_OK
    }

    def "csrf clears on logout"() {
        setup:
            CsrfTokenRepositoryConfig.repo = Mock(CsrfTokenRepository)
            1 * CsrfTokenRepositoryConfig.repo.loadToken(_) >> csrfToken
            loadConfig(CsrfTokenRepositoryConfig)
            login()
            request.method = "POST"
            request.servletPath = "/logout"
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            1 *  CsrfTokenRepositoryConfig.repo.saveToken(null, _, _)
    }

    def "csrf clears on login"() {
        setup:
            CsrfTokenRepositoryConfig.repo = Mock(CsrfTokenRepository)
            (1.._) * CsrfTokenRepositoryConfig.repo.loadToken(_) >> csrfToken
            loadConfig(CsrfTokenRepositoryConfig)
            request.method = "POST"
            request.getSession()
            request.servletPath = "/login"
            request.setParameter("username", "user")
            request.setParameter("password", "password")
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.redirectedUrl == "/"
            (1.._) *  CsrfTokenRepositoryConfig.repo.saveToken(null, _, _)
    }

    @Configuration
    @EnableWebSecurity
    static class CsrfTokenRepositoryConfig extends WebSecurityConfigurerAdapter {
        static CsrfTokenRepository repo

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .formLogin()
                    .and()
                .csrf()
                    .csrfTokenRepository(repo)
        }
        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER")
        }
    }

    def "csrf access denied handler"() {
        setup:
            AccessDeniedHandlerConfig.deniedHandler = Mock(AccessDeniedHandler)
            1 * AccessDeniedHandlerConfig.deniedHandler.handle(_, _, _)
            loadConfig(AccessDeniedHandlerConfig)
            clearCsrfToken()
            request.method = "POST"
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.status == HttpServletResponse.SC_OK
    }

    @Configuration
    @EnableWebSecurity
    static class AccessDeniedHandlerConfig extends WebSecurityConfigurerAdapter {
        static AccessDeniedHandler deniedHandler

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .exceptionHandling()
                    .accessDeniedHandler(deniedHandler)
        }
    }

    def "formLogin requires CSRF token"() {
        setup:
            loadConfig(FormLoginConfig)
            clearCsrfToken()
            request.setParameter("username", "user")
            request.setParameter("password", "password")
            request.servletPath = "/login"
            request.method = "POST"
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.status == HttpServletResponse.SC_FORBIDDEN
            currentAuthentication == null
    }

    @Configuration
    @EnableWebSecurity
    static class FormLoginConfig extends WebSecurityConfigurerAdapter {
        static AccessDeniedHandler deniedHandler

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .formLogin()
        }
    }

    def "logout requires CSRF token"() {
        setup:
            loadConfig(LogoutConfig)
            clearCsrfToken()
            login()
            request.servletPath = "/logout"
            request.method = "POST"
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then: "logout is not allowed and user is still authenticated"
            response.status == HttpServletResponse.SC_FORBIDDEN
            currentAuthentication != null
    }

    @Configuration
    @EnableWebSecurity
    static class LogoutConfig extends WebSecurityConfigurerAdapter {
        static AccessDeniedHandler deniedHandler

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .formLogin()
        }
    }

    def "csrf disables POST requests from RequestCache"() {
        setup:
            CsrfDisablesPostRequestFromRequestCacheConfig.repo = Mock(CsrfTokenRepository)
            loadConfig(CsrfDisablesPostRequestFromRequestCacheConfig)
            request.servletPath = "/some-url"
            request.requestURI = "/some-url"
            request.method = "POST"
        when: "CSRF passes and our session times out"
            springSecurityFilterChain.doFilter(request,response,chain)
        then: "sent to the login page"
            (1.._) * CsrfDisablesPostRequestFromRequestCacheConfig.repo.loadToken(_) >> csrfToken
            response.status == HttpServletResponse.SC_MOVED_TEMPORARILY
            response.redirectedUrl == "http://localhost/login"
        when: "authenticate successfully"
            super.setupWeb(request.session)
            request.servletPath = "/login"
            request.setParameter("username","user")
            request.setParameter("password","password")
            request.method = "POST"
            springSecurityFilterChain.doFilter(request,response,chain)
        then: "sent to default success because we don't want csrf attempts made prior to authentication to pass"
            (1.._) * CsrfDisablesPostRequestFromRequestCacheConfig.repo.loadToken(_) >> csrfToken
            response.status == HttpServletResponse.SC_MOVED_TEMPORARILY
            response.redirectedUrl == "/"
    }

    def "csrf enables GET requests with RequestCache"() {
        setup:
            CsrfDisablesPostRequestFromRequestCacheConfig.repo = Mock(CsrfTokenRepository)
            loadConfig(CsrfDisablesPostRequestFromRequestCacheConfig)
            request.servletPath = "/some-url"
            request.requestURI = "/some-url"
            request.method = "GET"
        when: "CSRF passes and our session times out"
            springSecurityFilterChain.doFilter(request,response,chain)
        then: "sent to the login page"
            (1.._) * CsrfDisablesPostRequestFromRequestCacheConfig.repo.loadToken(_) >> csrfToken
            response.status == HttpServletResponse.SC_MOVED_TEMPORARILY
            response.redirectedUrl == "http://localhost/login"
        when: "authenticate successfully"
            super.setupWeb(request.session)
            request.servletPath = "/login"
            request.setParameter("username","user")
            request.setParameter("password","password")
            request.method = "POST"
            springSecurityFilterChain.doFilter(request,response,chain)
        then: "sent to original URL since it was a GET"
            (1.._) * CsrfDisablesPostRequestFromRequestCacheConfig.repo.loadToken(_) >> csrfToken
            response.status == HttpServletResponse.SC_MOVED_TEMPORARILY
            response.redirectedUrl == "http://localhost/some-url"
    }

    @Configuration
    @EnableWebSecurity
    static class CsrfDisablesPostRequestFromRequestCacheConfig extends WebSecurityConfigurerAdapter {
        static CsrfTokenRepository repo

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .authorizeRequests()
                    .anyRequest().authenticated()
                    .and()
                .formLogin()
                    .and()
                .csrf()
                    .csrfTokenRepository(repo)
        }
        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER")
        }
    }

    def clearCsrfToken() {
        request.removeAllParameters()
    }
}
