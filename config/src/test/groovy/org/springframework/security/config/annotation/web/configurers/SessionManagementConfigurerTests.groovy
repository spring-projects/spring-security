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
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.SessionCreationPolicy;
import org.springframework.security.web.access.ExceptionTranslationFilter
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
                    .sessionCreationPolicy(SessionCreationPolicy.stateless)
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
                    .sessionCreationPolicy(SessionCreationPolicy.stateless)
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

        then: "SessionManagementFilter is registered with LifecycleManager"
            1 * opp.postProcess(_ as SessionManagementFilter) >> {SessionManagementFilter o -> o}
        and: "ConcurrentSessionFilter is registered with LifecycleManager"
            1 * opp.postProcess(_ as ConcurrentSessionFilter) >> {ConcurrentSessionFilter o -> o}
    }
}
