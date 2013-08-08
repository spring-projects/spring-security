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
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.ObjectPostProcessor
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.session.SessionRegistry
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy
import org.springframework.security.web.context.SecurityContextPersistenceFilter
import org.springframework.security.web.context.SecurityContextRepository
import org.springframework.security.web.session.ConcurrentSessionFilter
import org.springframework.security.web.session.SessionManagementFilter

/**
 *
 * @author Rob Winch
 */
class NamespaceSessionManagementTests extends BaseSpringSpec {

    def "http/session-management"() {
        when:
            loadConfig(SessionManagementConfig)
        then:
            findFilter(SessionManagementFilter).sessionAuthenticationStrategy instanceof SessionFixationProtectionStrategy
    }

    @EnableWebSecurity
    @Configuration
    static class SessionManagementConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            // enabled by default
        }
    }

    def "http/session-management custom"() {
        setup:
            CustomSessionManagementConfig.SR = Mock(SessionRegistry)
        when:
            loadConfig(CustomSessionManagementConfig)
            def concurrentStrategy = findFilter(SessionManagementFilter).sessionAuthenticationStrategy.delegateStrategies[0]
        then:
            findFilter(SessionManagementFilter).invalidSessionStrategy.destinationUrl == "/invalid-session"
            findFilter(SessionManagementFilter).failureHandler.defaultFailureUrl == "/session-auth-error"
            concurrentStrategy.maximumSessions == 1
            concurrentStrategy.exceptionIfMaximumExceeded
            concurrentStrategy.sessionRegistry == CustomSessionManagementConfig.SR
            findFilter(ConcurrentSessionFilter).expiredUrl == "/expired-session"
    }

    @EnableWebSecurity
    @Configuration
    static class CustomSessionManagementConfig extends WebSecurityConfigurerAdapter {
        static SessionRegistry SR
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .sessionManagement()
                    .invalidSessionUrl("/invalid-session") // session-management@invalid-session-url
                    .sessionAuthenticationErrorUrl("/session-auth-error") // session-management@session-authentication-error-url
                    .maximumSessions(1) // session-management/concurrency-control@max-sessions
                        .maxSessionsPreventsLogin(true) // session-management/concurrency-control@error-if-maximum-exceeded
                        .expiredUrl("/expired-session") // session-management/concurrency-control@expired-url
                        .sessionRegistry(SR) // session-management/concurrency-control@session-registry-ref
        }
    }

    def "http/session-management refs"() {
        setup:
            RefsSessionManagementConfig.SAS = Mock(SessionAuthenticationStrategy)
        when:
            loadConfig(RefsSessionManagementConfig)
        then:
            findFilter(SessionManagementFilter).sessionAuthenticationStrategy ==  RefsSessionManagementConfig.SAS
    }

    @EnableWebSecurity
    @Configuration
    static class RefsSessionManagementConfig extends WebSecurityConfigurerAdapter {
        static SessionAuthenticationStrategy SAS
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .sessionManagement()
                    .sessionAuthenticationStrategy(SAS) // session-management@session-authentication-strategy-ref
        }
    }

    def "http/session-management@session-fixation-protection=none"() {
        when:
            loadConfig(SFPNoneSessionManagementConfig)
        then:
            findFilter(SessionManagementFilter).sessionAuthenticationStrategy.class ==  NullAuthenticatedSessionStrategy
    }

    @EnableWebSecurity
    @Configuration
    static class SFPNoneSessionManagementConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .sessionManagement()
                    .sessionAuthenticationStrategy(new NullAuthenticatedSessionStrategy())
        }
    }

    def "http/session-management@session-fixation-protection=migrateSession (default)"() {
        when:
            loadConfig(SFPMigrateSessionManagementConfig)
        then:
            findFilter(SessionManagementFilter).sessionAuthenticationStrategy.migrateSessionAttributes
    }

    @EnableWebSecurity
    @Configuration
    static class SFPMigrateSessionManagementConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .sessionManagement()
        }
    }

    def "http/session-management@session-fixation-protection=newSession"() {
        when:
            loadConfig(SFPNewSessionSessionManagementConfig)
        then:
            !findFilter(SessionManagementFilter).sessionAuthenticationStrategy.migrateSessionAttributes
    }

    @EnableWebSecurity
    @Configuration
    static class SFPNewSessionSessionManagementConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .sessionManagement()
                    .sessionFixation()
                        .newSession()
        }
    }
}
