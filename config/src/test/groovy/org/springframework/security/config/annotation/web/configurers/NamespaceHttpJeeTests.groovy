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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.access.AccessDecisionManager
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute
import org.springframework.security.authentication.AnonymousAuthenticationToken
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.FilterChainProxy
import org.springframework.security.web.FilterInvocation
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedGrantedAuthoritiesUserDetailsService;
import org.springframework.security.web.authentication.preauth.j2ee.J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.preauth.j2ee.J2eePreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextPersistenceFilter
import org.springframework.security.web.jaasapi.JaasApiIntegrationFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.security.web.util.AntPathRequestMatcher
import org.springframework.security.web.util.AnyRequestMatcher;
import org.springframework.security.web.util.RequestMatcher
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Tests to verify that all the functionality of <jee> attributes is present
 *
 * @author Rob Winch
 *
 */
public class NamespaceHttpJeeTests extends BaseSpringSpec {

    def "http/jee@mappable-roles"() {
        when:
            loadConfig(JeeMappableRolesConfig)
            J2eePreAuthenticatedProcessingFilter filter = findFilter(J2eePreAuthenticatedProcessingFilter)
            AuthenticationManager authenticationManager = ReflectionTestUtils.getField(filter,"authenticationManager")
        then:
            authenticationManager
            filter.authenticationDetailsSource.class == J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource
            filter.authenticationDetailsSource.j2eeMappableRoles == ["ROLE_USER", "ROLE_ADMIN"] as Set
            authenticationManager.providers.find { it instanceof PreAuthenticatedAuthenticationProvider }.preAuthenticatedUserDetailsService.class == PreAuthenticatedGrantedAuthoritiesUserDetailsService
    }

    @Configuration
    @EnableWebSecurity
    public static class JeeMappableRolesConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .authorizeUrls()
                    .anyRequest().hasRole("USER")
                    .and()
                .jee()
                    .mappableRoles("USER","ADMIN");
        }
    }

    def "http/jee@user-service-ref"() {
        when:
            loadConfig(JeeUserServiceRefConfig)
            J2eePreAuthenticatedProcessingFilter filter = findFilter(J2eePreAuthenticatedProcessingFilter)
            AuthenticationManager authenticationManager = ReflectionTestUtils.getField(filter,"authenticationManager")
        then:
            authenticationManager
            filter.authenticationDetailsSource.class == J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource
            filter.authenticationDetailsSource.j2eeMappableRoles == ["ROLE_USER", "ROLE_ADMIN"] as Set
            authenticationManager.providers.find { it instanceof PreAuthenticatedAuthenticationProvider }.preAuthenticatedUserDetailsService.class == CustomUserService
    }

    @Configuration
    @EnableWebSecurity
    public static class JeeUserServiceRefConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .authorizeUrls()
                    .anyRequest().hasRole("USER")
                    .and()
                .jee()
                    .mappableAuthorities("ROLE_USER","ROLE_ADMIN")
                    .authenticatedUserDetailsService(new CustomUserService());
        }
    }

    static class CustomUserService implements AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {
        public UserDetails loadUserDetails(
                PreAuthenticatedAuthenticationToken token)
                throws UsernameNotFoundException {
            return null;
        }
    }
}
