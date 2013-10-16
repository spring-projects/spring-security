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
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.config.annotation.AnyObjectPostProcessor
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.authentication.session.CompositeSessionAuthenticationStrategy
import org.springframework.security.web.authentication.session.ConcurrentSessionControlAuthenticationStrategy
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy
import org.springframework.security.web.context.NullSecurityContextRepository
import org.springframework.security.web.context.SecurityContextPersistenceFilter
import org.springframework.security.web.context.SecurityContextRepository
import org.springframework.security.web.savedrequest.RequestCache
import org.springframework.security.web.session.ConcurrentSessionFilter
import org.springframework.security.web.session.SessionManagementFilter

/**
 *
 * @author Rob Winch
 */
class SessionManagementConfigurerTests extends BaseSpringSpec {

    def "sessionManagement does not override explicit RequestCache"() {
        setup:
            SessionManagementDoesNotOverrideExplicitRequestCacheConfig.REQUEST_CACHE = Mock(RequestCache)
        when:
            loadConfig(SessionManagementDoesNotOverrideExplicitRequestCacheConfig)
        then:
            findFilter(ExceptionTranslationFilter).requestCache == SessionManagementDoesNotOverrideExplicitRequestCacheConfig.REQUEST_CACHE
    }

    @EnableWebSecurity
    @Configuration
    static class SessionManagementDoesNotOverrideExplicitRequestCacheConfig extends WebSecurityConfigurerAdapter {
        static RequestCache REQUEST_CACHE

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .requestCache()
                    .requestCache(REQUEST_CACHE)
                    .and()
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        }

    }

    def "sessionManagement does not override explict SecurityContextRepository"() {
        setup:
            SessionManagementDoesNotOverrideExplicitSecurityContextRepositoryConfig.SECURITY_CONTEXT_REPO = Mock(SecurityContextRepository)
        when:
            loadConfig(SessionManagementDoesNotOverrideExplicitSecurityContextRepositoryConfig)
        then:
            findFilter(SecurityContextPersistenceFilter).repo == SessionManagementDoesNotOverrideExplicitSecurityContextRepositoryConfig.SECURITY_CONTEXT_REPO
    }

    @Configuration
    @EnableWebSecurity
    static class SessionManagementDoesNotOverrideExplicitSecurityContextRepositoryConfig extends WebSecurityConfigurerAdapter {
        static SecurityContextRepository SECURITY_CONTEXT_REPO

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .securityContext()
                    .securityContextRepository(SECURITY_CONTEXT_REPO)
                    .and()
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        }

    }

    def "invoke sessionManagement twice does not override"() {
        when:
            loadConfig(InvokeTwiceDoesNotOverride)
        then:
            findFilter(SecurityContextPersistenceFilter).repo.class == NullSecurityContextRepository
    }

    @Configuration
    @EnableWebSecurity
    static class InvokeTwiceDoesNotOverride extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    .and()
                .sessionManagement()
        }

    }

    def 'SEC-2137: disable session fixation and enable concurrency control'() {
        setup: "context where session fixation is disabled and concurrency control is enabled"
            loadConfig(DisableSessionFixationEnableConcurrencyControlConfig)
            String originalSessionId = request.session.id
            String credentials = "user:password"
            request.addHeader("Authorization", "Basic " + credentials.bytes.encodeBase64())
        when: "authenticate"
            springSecurityFilterChain.doFilter(request, response, new MockFilterChain())
        then: "session invalidate is not called"
            request.session.id == originalSessionId
    }

    @EnableWebSecurity
    @Configuration
    static class DisableSessionFixationEnableConcurrencyControlConfig extends WebSecurityConfigurerAdapter {
        @Override
        public void configure(HttpSecurity http) {
            http
                .httpBasic()
                    .and()
                .sessionManagement()
                    .sessionFixation().none()
                    .maximumSessions(1)
        }
        @Override
        protected void configure(AuthenticationManagerBuilder auth) {
            auth
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER")
        }
    }

    def 'session fixation and enable concurrency control'() {
        setup: "context where session fixation is disabled and concurrency control is enabled"
            loadConfig(ConcurrencyControlConfig)
        when: "authenticate successfully"
            request.servletPath = "/login"
            request.method = "POST"
            request.setParameter("username", "user");
            request.setParameter("password","password")
            springSecurityFilterChain.doFilter(request, response, chain)
        then: "authentication is sucessful"
            response.status == HttpServletResponse.SC_MOVED_TEMPORARILY
            response.redirectedUrl == "/"
        when: "authenticate with the same user"
            super.setup()
            request.servletPath = "/login"
            request.method = "POST"
            request.setParameter("username", "user");
            request.setParameter("password","password")
            springSecurityFilterChain.doFilter(request, response, chain)
        then:
            response.status == HttpServletResponse.SC_MOVED_TEMPORARILY
            response.redirectedUrl == '/login?error'
    }

    @EnableWebSecurity
    @Configuration
    static class ConcurrencyControlConfig extends WebSecurityConfigurerAdapter {
        @Override
        public void configure(HttpSecurity http) {
            http
                .formLogin()
                    .and()
                .sessionManagement()
                    .maximumSessions(1)
                        .maxSessionsPreventsLogin(true)
        }
        @Override
        protected void configure(AuthenticationManagerBuilder auth) {
            auth
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER")
        }
    }

    def "sessionManagement ObjectPostProcessor"() {
        setup:
            AnyObjectPostProcessor opp = Mock()
            HttpSecurity http = new HttpSecurity(opp, authenticationBldr, [:])
        when:
            http
                .sessionManagement()
                    .maximumSessions(1)
                        .and()
                    .and()
                .build()

        then: "SessionManagementFilter is registered with ObjectPostProcessor"
            1 * opp.postProcess(_ as SessionManagementFilter) >> {SessionManagementFilter o -> o}
        and: "ConcurrentSessionFilter is registered with ObjectPostProcessor"
            1 * opp.postProcess(_ as ConcurrentSessionFilter) >> {ConcurrentSessionFilter o -> o}
        and: "ConcurrentSessionControlAuthenticationStrategy is registered with ObjectPostProcessor"
            1 * opp.postProcess(_ as ConcurrentSessionControlAuthenticationStrategy) >> {ConcurrentSessionControlAuthenticationStrategy o -> o}
        and: "CompositeSessionAuthenticationStrategy is registered with ObjectPostProcessor"
            1 * opp.postProcess(_ as CompositeSessionAuthenticationStrategy) >> {CompositeSessionAuthenticationStrategy o -> o}
        and: "RegisterSessionAuthenticationStrategy is registered with ObjectPostProcessor"
            1 * opp.postProcess(_ as RegisterSessionAuthenticationStrategy) >> {RegisterSessionAuthenticationStrategy o -> o}
    }

    def "use sharedObject trustResolver"() {
        setup:
            SharedTrustResolverConfig.TR = Mock(AuthenticationTrustResolver)
        when:
            loadConfig(SharedTrustResolverConfig)
        then:
            findFilter(SecurityContextPersistenceFilter).repo.trustResolver == SharedTrustResolverConfig.TR
            findFilter(SessionManagementFilter).trustResolver == SharedTrustResolverConfig.TR
    }

    @Configuration
    @EnableWebSecurity
    static class SharedTrustResolverConfig extends WebSecurityConfigurerAdapter {
        static AuthenticationTrustResolver TR

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .setSharedObject(AuthenticationTrustResolver, TR)
        }
    }
}
