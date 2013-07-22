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

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.access.AccessDecisionManager
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute
import org.springframework.security.authentication.AnonymousAuthenticationToken
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.BaseWebConfig;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.FilterInvocation
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextPersistenceFilter
import org.springframework.security.web.jaasapi.JaasApiIntegrationFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.security.web.util.AntPathRequestMatcher
import org.springframework.security.web.util.AnyRequestMatcher;
import org.springframework.security.web.util.RequestMatcher

import spock.lang.Ignore;

/**
 * Tests to verify that all the functionality of <anonymous> attributes is present
 *
 * @author Rob Winch
 *
 */
public class NamespaceHttpCustomFilterTests extends BaseSpringSpec {
    def "http/custom-filter@before"() {
        when:
        loadConfig(CustomFilterBeforeConfig)
        then:
        filterChain().filters[0].class == CustomFilter
    }

    @Configuration
    static class CustomFilterBeforeConfig extends BaseWebConfig {
        CustomFilterBeforeConfig() {
            // do not add the default filters to make testing easier
            super(true)
        }

        protected void configure(HttpSecurity http) {
            http
                .addFilterBefore(new CustomFilter(), UsernamePasswordAuthenticationFilter.class)
                .formLogin()
        }
    }

    def "http/custom-filter@after"() {
        when:
        loadConfig(CustomFilterAfterConfig)
        then:
        filterChain().filters[1].class == CustomFilter
    }

    @Configuration
    static class CustomFilterAfterConfig extends BaseWebConfig {
        CustomFilterAfterConfig() {
            // do not add the default filters to make testing easier
            super(true)
        }

        protected void configure(HttpSecurity http) {
            http
                .addFilterAfter(new CustomFilter(), UsernamePasswordAuthenticationFilter.class)
                .formLogin()
        }
    }

    def "http/custom-filter@position"() {
        when:
        loadConfig(CustomFilterPositionConfig)
        then:
        filterChain().filters.collect { it.class } == [CustomFilter]
    }

    @Configuration
    static class CustomFilterPositionConfig extends BaseWebConfig {
        CustomFilterPositionConfig() {
            // do not add the default filters to make testing easier
            super(true)
        }

        protected void configure(HttpSecurity http) {
            http
                // this works so long as the CustomFilter extends one of the standard filters
                // if not, use addFilterBefore or addFilterAfter
                .addFilter(new CustomFilter())
        }

    }

    def "http/custom-filter no AuthenticationManager in HttpSecurity"() {
        when:
        loadConfig(NoAuthenticationManagerInHtppConfigurationConfig)
        then:
        filterChain().filters[0].class == CustomFilter
    }

    @Configuration
    @EnableWebSecurity
    static class NoAuthenticationManagerInHtppConfigurationConfig extends WebSecurityConfigurerAdapter {
        NoAuthenticationManagerInHtppConfigurationConfig() {
            super(true)
        }

        protected AuthenticationManager authenticationManager()
                throws Exception {
            return new CustomAuthenticationManager();
        }

        @Override
        protected void configure(HttpSecurity http) {
            http
                .authorizeRequests()
                    .anyRequest().hasRole("USER")
                    .and()
                .addFilterBefore(new CustomFilter(), UsernamePasswordAuthenticationFilter.class)
        }
    }

    static class CustomFilter extends UsernamePasswordAuthenticationFilter {}

    static class CustomAuthenticationManager implements AuthenticationManager {
        public Authentication authenticate(Authentication authentication)
                throws AuthenticationException {
            return null;
        }
    }
}
