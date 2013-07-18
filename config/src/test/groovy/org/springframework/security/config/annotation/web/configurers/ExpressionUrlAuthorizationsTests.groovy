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

import javax.servlet.http.HttpServletResponse

import org.springframework.beans.factory.BeanCreationException
import org.springframework.context.annotation.Configuration
import org.springframework.security.access.vote.AffirmativeBased
import org.springframework.security.authentication.RememberMeAuthenticationToken
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.SecurityExpressions.*
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor

public class ExpressionUrlAuthorizationConfigurerTests extends BaseSpringSpec {

    def "hasAnyAuthority('ROLE_USER')"() {
        when:
            def expression = ExpressionUrlAuthorizationConfigurer.hasAnyAuthority("ROLE_USER")
        then:
            expression == "hasAnyAuthority('ROLE_USER')"
    }

    def "hasAnyAuthority('ROLE_USER','ROLE_ADMIN')"() {
        when:
            def expression = ExpressionUrlAuthorizationConfigurer.hasAnyAuthority("ROLE_USER","ROLE_ADMIN")
        then:
            expression == "hasAnyAuthority('ROLE_USER','ROLE_ADMIN')"
    }

    def "hasRole('ROLE_USER') is rejected due to starting with ROLE_"() {
        when:
            def expression = ExpressionUrlAuthorizationConfigurer.hasRole("ROLE_USER")
        then:
            IllegalArgumentException e = thrown()
            e.message == "role should not start with 'ROLE_' since it is automatically inserted. Got 'ROLE_USER'"
    }

    def "authorizeUrls() uses AffirmativeBased AccessDecisionManager"() {
        when: "Load Config with no specific AccessDecisionManager"
            loadConfig(NoSpecificAccessDecessionManagerConfig)
        then: "AccessDecessionManager matches the HttpSecurityBuilder's default"
            findFilter(FilterSecurityInterceptor).accessDecisionManager.class == AffirmativeBased
    }

    @EnableWebSecurity
    @Configuration
    static class NoSpecificAccessDecessionManagerConfig extends WebSecurityConfigurerAdapter {
        protected void configure(HttpSecurity http) throws Exception {
            http
                .authorizeUrls()
                    .anyRequest().hasRole("USER")
        }
    }

    def "authorizeUrls() no requests"() {
        when: "Load Config with no requests"
            loadConfig(NoRequestsConfig)
        then: "A meaningful exception is thrown"
            BeanCreationException success = thrown()
            success.message.contains "At least one mapping is required (i.e. authorizeUrls().anyRequest.authenticated())"
    }

    @EnableWebSecurity
    @Configuration
    static class NoRequestsConfig extends WebSecurityConfigurerAdapter {
        protected void configure(HttpSecurity http) throws Exception {
            http
                .authorizeUrls()
        }
    }

    def "authorizeUrls() incomplete mapping"() {
        when: "Load Config with incomplete mapping"
            loadConfig(IncompleteMappingConfig)
        then: "A meaningful exception is thrown"
            BeanCreationException success = thrown()
            success.message.contains "An incomplete mapping was found for "
    }

    @EnableWebSecurity
    @Configuration
    static class IncompleteMappingConfig extends WebSecurityConfigurerAdapter {
        protected void configure(HttpSecurity http) throws Exception {
            http
                .authorizeUrls()
                    .antMatchers("/a").authenticated()
                    .anyRequest()
        }
    }

    def "authorizeUrls() hasAuthority"() {
        setup:
            loadConfig(HasAuthorityConfig)
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.status == HttpServletResponse.SC_UNAUTHORIZED
        when:
            super.setup()
            login()
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.status == HttpServletResponse.SC_OK
        when:
            super.setup()
            login("user","ROLE_INVALID")
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.status == HttpServletResponse.SC_FORBIDDEN
    }

    @EnableWebSecurity
    @Configuration
    static class HasAuthorityConfig extends WebSecurityConfigurerAdapter {
        protected void configure(HttpSecurity http) throws Exception {
            http
                .httpBasic()
                    .and()
                .authorizeUrls()
                    .anyRequest().hasAuthority("ROLE_USER")
        }
    }

    def "authorizeUrls() hasAnyAuthority"() {
        setup:
            loadConfig(HasAnyAuthorityConfig)
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.status == HttpServletResponse.SC_UNAUTHORIZED
        when:
            super.setup()
            login("user","ROLE_ADMIN")
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.status == HttpServletResponse.SC_OK
        when:
            super.setup()
            login("user","ROLE_DBA")
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.status == HttpServletResponse.SC_OK
        when:
            super.setup()
            login("user","ROLE_INVALID")
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.status == HttpServletResponse.SC_FORBIDDEN
    }

    @EnableWebSecurity
    @Configuration
    static class HasAnyAuthorityConfig extends WebSecurityConfigurerAdapter {
        protected void configure(HttpSecurity http) throws Exception {
            http
                .httpBasic()
                    .and()
                .authorizeUrls()
                    .anyRequest().hasAnyAuthority("ROLE_ADMIN","ROLE_DBA")
        }
    }

    def "authorizeUrls() hasIpAddress"() {
        setup:
            loadConfig(HasIpAddressConfig)
        when:
            request.remoteAddr = "192.168.1.1"
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.status == HttpServletResponse.SC_UNAUTHORIZED
        when:
            super.setup()
            request.remoteAddr = "192.168.1.0"
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.status == HttpServletResponse.SC_OK
    }

    @EnableWebSecurity
    @Configuration
    static class HasIpAddressConfig extends WebSecurityConfigurerAdapter {
        protected void configure(HttpSecurity http) throws Exception {
            http
                .httpBasic()
                    .and()
                .authorizeUrls()
                    .anyRequest().hasIpAddress("192.168.1.0")
        }
    }

    def "authorizeUrls() anonymous"() {
        setup:
            loadConfig(AnonymousConfig)
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.status == HttpServletResponse.SC_OK
        when:
            super.setup()
            login()
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.status == HttpServletResponse.SC_FORBIDDEN
    }

    @EnableWebSecurity
    @Configuration
    static class AnonymousConfig extends WebSecurityConfigurerAdapter {
        protected void configure(HttpSecurity http) throws Exception {
            http
                .httpBasic()
                    .and()
                .authorizeUrls()
                    .anyRequest().anonymous()
        }
    }

    def "authorizeUrls() rememberMe"() {
        setup:
            loadConfig(RememberMeConfig)
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.status == HttpServletResponse.SC_UNAUTHORIZED
        when:
            super.setup()
            login(new RememberMeAuthenticationToken("key", "user", AuthorityUtils.createAuthorityList("ROLE_USER")))
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.status == HttpServletResponse.SC_OK
    }

    @EnableWebSecurity
    @Configuration
    static class RememberMeConfig extends WebSecurityConfigurerAdapter {
        protected void configure(HttpSecurity http) throws Exception {
            http
                .rememberMe()
                    .and()
                .httpBasic()
                    .and()
                .authorizeUrls()
                    .anyRequest().rememberMe()
        }

        @Override
        protected void registerAuthentication(AuthenticationManagerBuilder auth)
                throws Exception {
            auth
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER")
        }
    }

    def "authorizeUrls() denyAll"() {
        setup:
            loadConfig(DenyAllConfig)
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.status == HttpServletResponse.SC_UNAUTHORIZED
        when:
            super.setup()
            login(new RememberMeAuthenticationToken("key", "user", AuthorityUtils.createAuthorityList("ROLE_USER")))
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.status == HttpServletResponse.SC_FORBIDDEN
    }

    @EnableWebSecurity
    @Configuration
    static class DenyAllConfig extends WebSecurityConfigurerAdapter {
        protected void configure(HttpSecurity http) throws Exception {
            http
                .httpBasic()
                    .and()
                .authorizeUrls()
                    .anyRequest().denyAll()
        }
    }

    def "authorizeUrls() not denyAll"() {
        setup:
            loadConfig(NotDenyAllConfig)
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.status == HttpServletResponse.SC_OK
        when:
            super.setup()
            login(new RememberMeAuthenticationToken("key", "user", AuthorityUtils.createAuthorityList("ROLE_USER")))
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.status == HttpServletResponse.SC_OK
    }

    @EnableWebSecurity
    @Configuration
    static class NotDenyAllConfig extends WebSecurityConfigurerAdapter {
        protected void configure(HttpSecurity http) throws Exception {
            http
                .httpBasic()
                    .and()
                .authorizeUrls()
                    .anyRequest().not().denyAll()
        }
    }

    def "authorizeUrls() fullyAuthenticated"() {
        setup:
            loadConfig(FullyAuthenticatedConfig)
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.status == HttpServletResponse.SC_UNAUTHORIZED
        when:
            super.setup()
            login(new RememberMeAuthenticationToken("key", "user", AuthorityUtils.createAuthorityList("ROLE_USER")))
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.status == HttpServletResponse.SC_FORBIDDEN
        when:
            super.setup()
            login()
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.status == HttpServletResponse.SC_OK
    }

    @EnableWebSecurity
    @Configuration
    static class FullyAuthenticatedConfig extends WebSecurityConfigurerAdapter {
        protected void configure(HttpSecurity http) throws Exception {
            http
                .rememberMe()
                    .and()
                .httpBasic()
                    .and()
                .authorizeUrls()
                    .anyRequest().fullyAuthenticated()
        }

        @Override
        protected void registerAuthentication(AuthenticationManagerBuilder auth)
                throws Exception {
            auth
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER")
        }
    }

    def "authorizeUrls() access"() {
        setup:
            loadConfig(AccessConfig)
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then: "Access is granted due to GET"
            response.status == HttpServletResponse.SC_OK
        when:
            super.setup()
            login()
            request.method = "POST"
            springSecurityFilterChain.doFilter(request,response,chain)
        then: "Access is granted due to role"
            response.status == HttpServletResponse.SC_OK
        when:
            super.setup()
            request.method = "POST"
            springSecurityFilterChain.doFilter(request,response,chain)
        then: "Access is denied"
            response.status == HttpServletResponse.SC_UNAUTHORIZED
    }

    @EnableWebSecurity
    @Configuration
    static class AccessConfig extends WebSecurityConfigurerAdapter {
        protected void configure(HttpSecurity http) throws Exception {
            http
                .rememberMe()
                    .and()
                .httpBasic()
                    .and()
                .authorizeUrls()
                    .anyRequest().access("hasRole('ROLE_USER') or request.method == 'GET'")
        }

        @Override
        protected void registerAuthentication(AuthenticationManagerBuilder auth)
                throws Exception {
            auth
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER")
        }
    }
}
