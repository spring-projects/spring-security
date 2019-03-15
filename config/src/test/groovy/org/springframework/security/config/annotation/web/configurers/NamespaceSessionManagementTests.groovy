/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation.web.configurers

import org.springframework.context.ApplicationListener
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.core.session.SessionRegistry
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy
import org.springframework.security.web.authentication.session.SessionFixationProtectionEvent
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy
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
            findSessionAuthenticationStrategy(SessionFixationProtectionStrategy)
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
            findFilter(SessionManagementFilter).sessionAuthenticationStrategy.delegateStrategies.find { it ==  RefsSessionManagementConfig.SAS }
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
            findFilter(SessionManagementFilter).sessionAuthenticationStrategy.delegateStrategies.find { it instanceof  NullAuthenticatedSessionStrategy }
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
            findSessionAuthenticationStrategy(SessionFixationProtectionStrategy).migrateSessionAttributes
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

    def "SEC-2913: Default JavaConfig session fixation AuthenticationStrategy has NullEventPublisher"() {
        setup:
            loadConfig(SFPPostProcessedConfig)
        when:
            findSessionAuthenticationStrategy(SessionFixationProtectionStrategy).onSessionChange("id", new MockHttpSession(), new TestingAuthenticationToken("u","p","ROLE_USER"))
        then:
            context.getBean(MockEventListener).events
    }

    @EnableWebSecurity
    static class SFPPostProcessedConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .sessionManagement()
        }

        @Bean
        public MockEventListener eventListener() {
            new MockEventListener()
        }
    }

    def "http/session-management@session-fixation-protection=newSession"() {
        when:
            loadConfig(SFPNewSessionSessionManagementConfig)
        then:
            !findSessionAuthenticationStrategy(SessionFixationProtectionStrategy).migrateSessionAttributes
    }

    def findSessionAuthenticationStrategy(def c) {
        findFilter(SessionManagementFilter).sessionAuthenticationStrategy.delegateStrategies.find { it.class.isAssignableFrom(c) }
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

    static class MockEventListener implements ApplicationListener<SessionFixationProtectionEvent> {
        List<SessionFixationProtectionEvent> events = []

        public void onApplicationEvent(SessionFixationProtectionEvent event) {
            events.add(event)
        }

    }
}
