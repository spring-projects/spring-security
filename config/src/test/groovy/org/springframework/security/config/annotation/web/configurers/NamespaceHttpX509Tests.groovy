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

import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

import javax.servlet.http.HttpServletRequest

import org.springframework.context.annotation.Configuration
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.authentication.AuthenticationDetailsSource
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.web.FilterChainProxy
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken
import org.springframework.security.web.authentication.preauth.PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter
import org.springframework.security.web.context.HttpRequestResponseHolder
import org.springframework.security.web.context.HttpSessionSecurityContextRepository
import org.springframework.test.util.ReflectionTestUtils

/**
 * Tests to verify that all the functionality of <jee> attributes is present
 *
 * @author Rob Winch
 *
 */
public class NamespaceHttpX509Tests extends BaseSpringSpec {
    FilterChainProxy springSecurityFilterChain
    MockHttpServletRequest request
    MockHttpServletResponse response
    MockFilterChain chain

    def setup() {
        request = new MockHttpServletRequest()
        response = new MockHttpServletResponse()
        chain = new MockFilterChain()
    }

    def "http/x509 can authenticate"() {
        setup:
            X509Certificate certificate = loadCert("rod.cer")
            loadConfig(X509Config)
            springSecurityFilterChain = context.getBean(FilterChainProxy)
        when:
            request.setAttribute("javax.servlet.request.X509Certificate", [certificate] as X509Certificate[] )
            springSecurityFilterChain.doFilter(request, response, chain);
        then:
            response.status == 200
            authentication().name == 'rod'
    }

    def "http/x509"() {
        when:
            loadConfig(X509Config)
            X509AuthenticationFilter filter = findFilter(X509AuthenticationFilter)
            AuthenticationManager authenticationManager = ReflectionTestUtils.getField(filter,"authenticationManager")
        then:
            authenticationManager
            filter.authenticationDetailsSource.class == WebAuthenticationDetailsSource
            authenticationManager.providers.find { it instanceof PreAuthenticatedAuthenticationProvider }.preAuthenticatedUserDetailsService.class == UserDetailsByNameServiceWrapper
    }

    @Configuration
    @EnableWebSecurity
    public static class X509Config extends WebSecurityConfigurerAdapter {
        @Override
        protected void registerAuthentication(AuthenticationManagerBuilder auth) throws Exception {
            auth.
                inMemoryAuthentication()
                    .withUser("rod").password("password").roles("USER","ADMIN");
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .authorizeRequests()
                    .anyRequest().hasRole("USER")
                    .and()
                .x509();
        }
    }

    def "http/x509@authentication-details-source-ref"() {
        setup:
            AuthenticationDetailsSourceRefConfig.AUTHENTICATION_DETAILS_SOURCE = Mock(AuthenticationDetailsSource)
        when:
            loadConfig(AuthenticationDetailsSourceRefConfig)
            X509AuthenticationFilter filter = findFilter(X509AuthenticationFilter)
            AuthenticationManager authenticationManager = ReflectionTestUtils.getField(filter,"authenticationManager")
        then:
            authenticationManager
            filter.authenticationDetailsSource == AuthenticationDetailsSourceRefConfig.AUTHENTICATION_DETAILS_SOURCE
            authenticationManager.providers.find { it instanceof PreAuthenticatedAuthenticationProvider }.preAuthenticatedUserDetailsService.class == UserDetailsByNameServiceWrapper
    }

    @Configuration
    @EnableWebSecurity
    public static class AuthenticationDetailsSourceRefConfig extends WebSecurityConfigurerAdapter {
        static AuthenticationDetailsSource<HttpServletRequest, PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails> AUTHENTICATION_DETAILS_SOURCE

        protected void registerAuthentication(AuthenticationManagerBuilder auth) throws Exception {
            auth.
                inMemoryAuthentication()
                    .withUser("rod").password("password").roles("USER","ADMIN");
        }

        protected void configure(HttpSecurity http) throws Exception {
            http
                .authorizeRequests()
                    .anyRequest().hasRole("USER")
                    .and()
                .x509()
                    .authenticationDetailsSource(AUTHENTICATION_DETAILS_SOURCE);
        }
    }

    def "http/x509@subject-principal-regex"() {
        setup:
            X509Certificate certificate = loadCert("rodatexampledotcom.cer")
            loadConfig(SubjectPrincipalRegexConfig)
            springSecurityFilterChain = context.getBean(FilterChainProxy)
        when:
            request.setAttribute("javax.servlet.request.X509Certificate", [certificate] as X509Certificate[] )
            springSecurityFilterChain.doFilter(request, response, chain);
        then:
            response.status == 200
            authentication().name == 'rod'
    }

    @Configuration
    @EnableWebSecurity
    public static class SubjectPrincipalRegexConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void registerAuthentication(AuthenticationManagerBuilder auth) throws Exception {
            auth.
                inMemoryAuthentication()
                    .withUser("rod").password("password").roles("USER","ADMIN");
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .authorizeRequests()
                    .anyRequest().hasRole("USER")
                    .and()
                .x509()
                    .subjectPrincipalRegex('CN=(.*?)@example.com(?:,|$)');
        }
    }

    def "http/x509@user-service-ref"() {
        setup:
            X509Certificate certificate = loadCert("rodatexampledotcom.cer")
            loadConfig(UserDetailsServiceRefConfig)
            springSecurityFilterChain = context.getBean(FilterChainProxy)
        when:
            request.setAttribute("javax.servlet.request.X509Certificate", [certificate] as X509Certificate[] )
            springSecurityFilterChain.doFilter(request, response, chain);
        then:
            response.status == 200
            authentication().name == 'customuser'
    }

    @Configuration
    @EnableWebSecurity
    public static class UserDetailsServiceRefConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void registerAuthentication(AuthenticationManagerBuilder auth) throws Exception {
            auth.
                inMemoryAuthentication()
                    .withUser("rod").password("password").roles("USER","ADMIN");
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .authorizeRequests()
                    .anyRequest().hasRole("USER")
                    .and()
                .x509()
                    .userDetailsService(new CustomUserDetailsService());
        }
    }

    def "http/x509 custom AuthenticationUserDetailsService"() {
        setup:
            X509Certificate certificate = loadCert("rodatexampledotcom.cer")
            loadConfig(AuthenticationUserDetailsServiceConfig)
            springSecurityFilterChain = context.getBean(FilterChainProxy)
        when:
            request.setAttribute("javax.servlet.request.X509Certificate", [certificate] as X509Certificate[] )
            springSecurityFilterChain.doFilter(request, response, chain);
        then:
            response.status == 200
            authentication().name == 'customuser'
    }

    @Configuration
    @EnableWebSecurity
    public static class AuthenticationUserDetailsServiceConfig extends WebSecurityConfigurerAdapter {
        static AuthenticationDetailsSource<HttpServletRequest, PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails> AUTHENTICATION_DETAILS_SOURCE

        protected void registerAuthentication(AuthenticationManagerBuilder auth) throws Exception {
            auth.
                inMemoryAuthentication()
                    .withUser("rod").password("password").roles("USER","ADMIN");
        }

        protected void configure(HttpSecurity http) throws Exception {
            http
                .authorizeRequests()
                    .anyRequest().hasRole("USER")
                    .and()
                .x509()
                    .userDetailsService(new CustomUserDetailsService());
        }
    }

    def loadCert(String location) {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        certFactory.generateCertificate(Thread.currentThread().contextClassLoader.getResourceAsStream(location))
    }

    static class CustomUserDetailsService implements UserDetailsService {

        public UserDetails loadUserByUsername(String username)
                throws UsernameNotFoundException {
            return new User("customuser", "password", AuthorityUtils.createAuthorityList("ROLE_USER"));
        }

    }

    static class CustomAuthenticationUserDetailsService implements AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {
        public UserDetails loadUserDetails(
                PreAuthenticatedAuthenticationToken token)
                throws UsernameNotFoundException {
            return new User("customuser", "password", AuthorityUtils.createAuthorityList("ROLE_USER"));
        }
    }

    def authentication() {
        HttpRequestResponseHolder requestResponseHolder = new HttpRequestResponseHolder(request, response)
        new HttpSessionSecurityContextRepository().loadContext(requestResponseHolder)?.authentication
    }
}
