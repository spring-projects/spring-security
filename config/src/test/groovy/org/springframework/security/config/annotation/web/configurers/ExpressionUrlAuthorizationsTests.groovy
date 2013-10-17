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

import static org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurerConfigs.*

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

    def "hasAnyRole('USER')"() {
        when:
            def expression = ExpressionUrlAuthorizationConfigurer.hasAnyRole("USER")
        then:
            expression == "hasAnyRole('ROLE_USER')"
    }

    def "hasAnyRole('USER','ADMIN')"() {
        when:
            def expression = ExpressionUrlAuthorizationConfigurer.hasAnyRole("USER","ADMIN")
        then:
            expression == "hasAnyRole('ROLE_USER','ROLE_ADMIN')"
    }

    def "hasRole('ROLE_USER') is rejected due to starting with ROLE_"() {
        when:
            def expression = ExpressionUrlAuthorizationConfigurer.hasRole("ROLE_USER")
        then:
            IllegalArgumentException e = thrown()
            e.message == "role should not start with 'ROLE_' since it is automatically inserted. Got 'ROLE_USER'"
    }

    def "authorizeRequests() uses AffirmativeBased AccessDecisionManager"() {
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
                .authorizeRequests()
                    .anyRequest().hasRole("USER")
        }
    }

    def "authorizeRequests() no requests"() {
        when: "Load Config with no requests"
            loadConfig(NoRequestsConfig)
        then: "A meaningful exception is thrown"
            BeanCreationException success = thrown()
            success.message.contains "At least one mapping is required (i.e. authorizeRequests().anyRequest.authenticated())"
    }

    @EnableWebSecurity
    @Configuration
    static class NoRequestsConfig extends WebSecurityConfigurerAdapter {
        protected void configure(HttpSecurity http) throws Exception {
            http
                .authorizeRequests()
        }
    }

    def "authorizeRequests() incomplete mapping"() {
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
                .authorizeRequests()
                    .antMatchers("/a").authenticated()
                    .anyRequest()
        }
    }

    def "authorizeRequests() hasAuthority"() {
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
                .authorizeRequests()
                    .anyRequest().hasAuthority("ROLE_USER")
        }
    }

    def "authorizeRequests() hasAnyAuthority"() {
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
                .authorizeRequests()
                    .anyRequest().hasAnyAuthority("ROLE_ADMIN","ROLE_DBA")
        }
    }

    def "authorizeRequests() hasIpAddress"() {
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
                .authorizeRequests()
                    .anyRequest().hasIpAddress("192.168.1.0")
        }
    }

    def "authorizeRequests() anonymous"() {
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
                .authorizeRequests()
                    .anyRequest().anonymous()
        }
    }

    def "authorizeRequests() rememberMe"() {
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
                .authorizeRequests()
                    .anyRequest().rememberMe()
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER")
        }
    }

    def "authorizeRequests() denyAll"() {
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
                .authorizeRequests()
                    .anyRequest().denyAll()
        }
    }

    def "authorizeRequests() not denyAll"() {
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
                .authorizeRequests()
                    .anyRequest().not().denyAll()
        }
    }

    def "authorizeRequests() fullyAuthenticated"() {
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
                .authorizeRequests()
                    .anyRequest().fullyAuthenticated()
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER")
        }
    }

    def "authorizeRequests() access"() {
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
                .authorizeRequests()
                    .anyRequest().access("hasRole('ROLE_USER') or request.method == 'GET'")
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER")
        }
    }


    def "invoke authorizeUrls twice does not reset"() {
        setup:
            loadConfig(InvokeTwiceDoesNotResetConfig)
        when:
            request.method = "POST"
            springSecurityFilterChain.doFilter(request,response,chain)
        then: "Access is denied"
            response.status == HttpServletResponse.SC_UNAUTHORIZED
    }

    @EnableWebSecurity
    @Configuration
    static class InvokeTwiceDoesNotResetConfig extends WebSecurityConfigurerAdapter {
        protected void configure(HttpSecurity http) throws Exception {
            http
                .httpBasic()
                    .and()
                .authorizeRequests()
                    .anyRequest().authenticated()
                    .and()
                .authorizeRequests()
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                .inMemoryAuthentication()
        }
    }

    def "All Properties are accessible and chain properly"() {
        when:
            loadConfig(AllPropertiesWorkConfig)
        then:
            noExceptionThrown()
    }
}
