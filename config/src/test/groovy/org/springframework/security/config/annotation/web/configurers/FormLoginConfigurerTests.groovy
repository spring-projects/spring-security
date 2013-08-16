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

import org.springframework.context.annotation.AnnotationConfigApplicationContext
import org.springframework.context.annotation.Configuration
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.config.annotation.AnyObjectPostProcessor
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.builders.WebSecurity
import org.springframework.security.config.annotation.web.configuration.BaseWebConfig
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.FilterChainProxy
import org.springframework.security.web.PortMapper
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.authentication.logout.LogoutFilter
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy
import org.springframework.security.web.context.SecurityContextPersistenceFilter
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter
import org.springframework.security.web.csrf.CsrfFilter
import org.springframework.security.web.header.HeaderWriterFilter
import org.springframework.security.web.savedrequest.RequestCacheAwareFilter
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter
import org.springframework.security.web.session.SessionManagementFilter
import org.springframework.security.web.util.AnyRequestMatcher
import org.springframework.test.util.ReflectionTestUtils

import spock.lang.Unroll

/**
 *
 * @author Rob Winch
 */
class FormLoginConfigurerTests extends BaseSpringSpec {
    def "Form Login"() {
        when: "load formLogin()"
            context = new AnnotationConfigApplicationContext(FormLoginConfig)

        then: "FilterChains configured correctly"
            def filterChains = filterChains()
            filterChains.size() == 2
            filterChains[0].requestMatcher.pattern == '/resources/**'
            filterChains[0].filters.empty
            filterChains[1].requestMatcher instanceof AnyRequestMatcher
            filterChains[1].filters.collect { it.class.name.contains('$') ? it.class.superclass : it.class } ==
                    [WebAsyncManagerIntegrationFilter, SecurityContextPersistenceFilter, HeaderWriterFilter, CsrfFilter, LogoutFilter, UsernamePasswordAuthenticationFilter,
                     RequestCacheAwareFilter, SecurityContextHolderAwareRequestFilter,
                     AnonymousAuthenticationFilter, SessionManagementFilter, ExceptionTranslationFilter, FilterSecurityInterceptor ]

        and: "UsernamePasswordAuthentictionFilter is configured correctly"
            UsernamePasswordAuthenticationFilter authFilter = findFilter(UsernamePasswordAuthenticationFilter,1)
            authFilter.usernameParameter == "username"
            authFilter.passwordParameter == "password"
            authFilter.failureHandler.defaultFailureUrl == "/login?error"
            authFilter.successHandler.defaultTargetUrl == "/"
            authFilter.requiresAuthentication(new MockHttpServletRequest(servletPath : "/login", method: "POST"), new MockHttpServletResponse())
            !authFilter.requiresAuthentication(new MockHttpServletRequest(servletPath : "/login", method: "GET"), new MockHttpServletResponse())

        and: "SessionFixationProtectionStrategy is configured correctly"
            SessionFixationProtectionStrategy sessionStrategy = ReflectionTestUtils.getField(authFilter,"sessionStrategy").delegateStrategies.find { SessionFixationProtectionStrategy }
            sessionStrategy.migrateSessionAttributes

        and: "Exception handling is configured correctly"
            AuthenticationEntryPoint authEntryPoint = filterChains[1].filters.find { it instanceof ExceptionTranslationFilter}.authenticationEntryPoint
            MockHttpServletResponse response = new MockHttpServletResponse()
            authEntryPoint.commence(new MockHttpServletRequest(servletPath: "/private/"), response, new BadCredentialsException(""))
            response.redirectedUrl == "http://localhost/login"
    }

    @Configuration
    @EnableWebSecurity
    static class FormLoginConfig extends BaseWebConfig {
        @Override
        public void configure(WebSecurity web)	throws Exception {
            web
                .ignoring()
                    .antMatchers("/resources/**");
        }

        @Override
        protected void configure(HttpSecurity http) {
            http
                .authorizeRequests()
                    .anyRequest().hasRole("USER")
                    .and()
                .formLogin()
                    .loginPage("/login")
        }
    }

    def "FormLogin.permitAll()"() {
        when: "load formLogin() with permitAll"
            context = new AnnotationConfigApplicationContext(FormLoginConfigPermitAll)
            FilterChainProxy filterChain = context.getBean(FilterChainProxy)
            MockHttpServletResponse response = new MockHttpServletResponse()
            request = new MockHttpServletRequest(servletPath : servletPath, requestURI: servletPath, queryString: query, method: method)
            setupCsrf()

        then: "the formLogin URLs are granted access"
            filterChain.doFilter(request, response, new MockFilterChain())
            response.redirectedUrl == redirectUrl

        where:
            servletPath | method | query | redirectUrl
            "/login" | "GET" | null | null
            "/login" | "POST" | null | "/login?error"
            "/login" | "GET" | "error" | null
    }

    @Configuration
    @EnableWebSecurity
    static class FormLoginConfigPermitAll extends BaseWebConfig {

        @Override
        protected void configure(HttpSecurity http) {
            http
                .authorizeRequests()
                    .anyRequest().hasRole("USER")
                    .and()
                .formLogin()
                    .permitAll()
        }
    }

    @Unroll
    def "FormLogin loginConventions changes defaults"() {
        when: "load formLogin() with permitAll"
            loadConfig(FormLoginDefaultsConfig)
            MockHttpServletResponse response = new MockHttpServletResponse()
            request = new MockHttpServletRequest(servletPath : servletPath, requestURI: servletPath, queryString: query, method: method)
            setupCsrf()

        then: "the other default login/logout URLs are updated and granted access"
            springSecurityFilterChain.doFilter(request, response, new MockFilterChain())
            response.redirectedUrl == redirectUrl

        where:
            servletPath     | method | query | redirectUrl
            "/authenticate" | "GET"  | null    | null
            "/authenticate" | "POST" | null    | "/authenticate?error"
            "/authenticate" | "GET"  | "error" | null
            "/logout"       | "POST" | null    | "/authenticate?logout"
            "/authenticate" | "GET"  | "logout"| null
    }

    @Configuration
    @EnableWebSecurity
    static class FormLoginDefaultsConfig extends BaseWebConfig {

        @Override
        protected void configure(HttpSecurity http) {
            http
                .authorizeRequests()
                    .anyRequest().hasRole("USER")
                    .and()
                .formLogin()
                    .loginPage("/authenticate")
                    .permitAll()
                    .and()
                .logout()
                    .permitAll()
        }
    }

    def "FormLogin uses PortMapper"() {
        when: "load formLogin() with permitAll"
            FormLoginUsesPortMapperConfig.PORT_MAPPER = Mock(PortMapper)
            loadConfig(FormLoginUsesPortMapperConfig)
        then: "the formLogin URLs are granted access"
            findFilter(ExceptionTranslationFilter).authenticationEntryPoint.portMapper == FormLoginUsesPortMapperConfig.PORT_MAPPER
    }

    @Configuration
    @EnableWebSecurity
    static class FormLoginUsesPortMapperConfig extends BaseWebConfig {
        static PortMapper PORT_MAPPER

        @Override
        protected void configure(HttpSecurity http) {
            http
                .authorizeRequests()
                    .anyRequest().hasRole("USER")
                    .and()
                .formLogin()
                    .permitAll()
                    .and()
                .portMapper()
                    .portMapper(PORT_MAPPER)
        }
    }

    def "FormLogin permitAll ignores failureUrl when failureHandler set"() {
        setup:
            PermitAllIgnoresFailureHandlerConfig.FAILURE_HANDLER = Mock(AuthenticationFailureHandler)
            loadConfig(PermitAllIgnoresFailureHandlerConfig)
            FilterChainProxy springSecurityFilterChain = context.getBean(FilterChainProxy)
        when: "access default failureUrl and configured explicit FailureHandler"
            MockHttpServletRequest request = new MockHttpServletRequest(servletPath:"/login",requestURI:"/login",queryString:"error",method:"GET")
            MockHttpServletResponse response = new MockHttpServletResponse()
            springSecurityFilterChain.doFilter(request,response,new MockFilterChain())
        then: "access is not granted to the failure handler (sent to login page)"
            response.status == 302
    }

    @EnableWebSecurity
    @Configuration
    static class PermitAllIgnoresFailureHandlerConfig extends BaseWebConfig {
        static AuthenticationFailureHandler FAILURE_HANDLER

        @Override
        protected void configure(HttpSecurity http) {
            http
                .authorizeRequests()
                    .anyRequest().hasRole("USER")
                    .and()
                .formLogin()
                    .failureHandler(FAILURE_HANDLER)
                    .permitAll()
        }
    }

    def "duplicate formLogin does not override"() {
        setup:
            DuplicateInvocationsDoesNotOverrideConfig.FAILURE_HANDLER = Mock(AuthenticationFailureHandler)
        when:
            loadConfig(DuplicateInvocationsDoesNotOverrideConfig)
        then:
            findFilter(UsernamePasswordAuthenticationFilter).usernameParameter == "custom-username"
    }

    @EnableWebSecurity
    @Configuration
    static class DuplicateInvocationsDoesNotOverrideConfig extends BaseWebConfig {
        static AuthenticationFailureHandler FAILURE_HANDLER

        @Override
        protected void configure(HttpSecurity http) {
            http
                .formLogin()
                    .usernameParameter("custom-username")
                    .and()
                .formLogin()
        }
    }

    def "formLogin ObjectPostProcessor"() {
        setup: "initialize the AUTH_FILTER as a mock"
            AnyObjectPostProcessor opp = Mock()
            HttpSecurity http = new HttpSecurity(opp, authenticationBldr, [:])
        when:
            http
                .exceptionHandling()
                    .and()
                .formLogin()
                    .and()
                .build()

        then: "UsernamePasswordAuthenticationFilter is registered with ObjectPostProcessor"
            1 * opp.postProcess(_ as UsernamePasswordAuthenticationFilter) >> {UsernamePasswordAuthenticationFilter o -> o}
        and: "LoginUrlAuthenticationEntryPoint is registered with ObjectPostProcessor"
            1 * opp.postProcess(_ as LoginUrlAuthenticationEntryPoint) >> {LoginUrlAuthenticationEntryPoint o -> o}
        and: "ExceptionTranslationFilter is registered with ObjectPostProcessor"
            1 * opp.postProcess(_ as ExceptionTranslationFilter) >> {ExceptionTranslationFilter o -> o}
    }
}
