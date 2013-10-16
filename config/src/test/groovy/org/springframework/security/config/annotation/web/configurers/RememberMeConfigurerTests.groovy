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

import javax.servlet.http.Cookie

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Configuration
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.authentication.RememberMeAuthenticationToken
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.AnyObjectPostProcessor
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter
import org.springframework.security.web.context.HttpRequestResponseHolder
import org.springframework.security.web.context.HttpSessionSecurityContextRepository

/**
 * Tests for RememberMeConfigurer that flex edge cases. {@link NamespaceRememberMeTests} demonstrate mapping of the XML namespace to Java Config.
 *
 * @author Rob Winch
 */
public class RememberMeConfigurerTests extends BaseSpringSpec {

    def "rememberMe() null UserDetailsService provides meaningful error"() {
        setup: "Load Config without UserDetailsService specified"
            loadConfig(NullUserDetailsConfig)
        when:
            request.setCookies(createRememberMeCookie())
            springSecurityFilterChain.doFilter(request, response, chain)
        then: "A good error message is provided"
            Exception success = thrown()
            success.message.contains "UserDetailsService is required"
    }

    @EnableWebSecurity
    @Configuration
    static class NullUserDetailsConfig extends WebSecurityConfigurerAdapter {
        protected void configure(HttpSecurity http) throws Exception {
            http
                .authorizeRequests()
                    .anyRequest().hasRole("USER")
                    .and()
                .formLogin()
                    .and()
                .rememberMe()
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            User user = new User("user", "password", AuthorityUtils.createAuthorityList("ROLE_USER"))
            DaoAuthenticationProvider provider = new DaoAuthenticationProvider()
            provider.userDetailsService = new InMemoryUserDetailsManager([user])
            auth
                .authenticationProvider(provider)
        }
    }

    def "rememberMe ObjectPostProcessor"() {
        setup:
            AnyObjectPostProcessor opp = Mock()
            HttpSecurity http = new HttpSecurity(opp, authenticationBldr, [:])
            UserDetailsService uds = authenticationBldr.getDefaultUserDetailsService()
        when:
            http
                .rememberMe()
                    .userDetailsService(authenticationBldr.getDefaultUserDetailsService())
                    .and()
                .build()

        then: "RememberMeAuthenticationFilter is registered with LifecycleManager"
            1 * opp.postProcess(_ as RememberMeAuthenticationFilter) >> {RememberMeAuthenticationFilter o -> o}
    }

    def "invoke rememberMe twice does not reset"() {
        setup:
            AnyObjectPostProcessor opp = Mock()
            HttpSecurity http = new HttpSecurity(opp, authenticationBldr, [:])
            UserDetailsService uds = authenticationBldr.getDefaultUserDetailsService()
        when:
            http
                .rememberMe()
                    .userDetailsService(authenticationBldr.getDefaultUserDetailsService())
                    .and()
                .rememberMe()
        then: "RememberMeAuthenticationFilter is registered with LifecycleManager"
            http.getConfigurer(RememberMeConfigurer).userDetailsService != null
    }


    def "http/remember-me with Global AuthenticationManagerBuilder"() {
        setup:
            loadConfig(RememberMeConfig)
        when: "login with remember me"
            super.setup()
            request.servletPath = "/login"
            request.method = "POST"
            request.parameters.username = ["user"] as String[]
            request.parameters.password = ["password"] as String[]
            request.parameters.'remember-me' = ["true"] as String[]
            springSecurityFilterChain.doFilter(request,response,chain)
            Cookie rememberMeCookie = getRememberMeCookie()
        then: "response contains remember me cookie"
            rememberMeCookie != null
        when: "session expires"
            super.setup()
            request.setCookies(rememberMeCookie)
            request.requestURI = "/abc"
            springSecurityFilterChain.doFilter(request,response,chain)
            MockHttpSession session = request.getSession()
        then: "initialized to RememberMeAuthenticationToken"
            SecurityContext context = new HttpSessionSecurityContextRepository().loadContext(new HttpRequestResponseHolder(request, response))
            context.getAuthentication() instanceof RememberMeAuthenticationToken
        when: "logout"
            super.setup()
            request.setSession(session)
            super.setupCsrf()
            request.setCookies(rememberMeCookie)
            request.servletPath = "/logout"
            request.method = "POST"
            springSecurityFilterChain.doFilter(request,response,chain)
            rememberMeCookie = getRememberMeCookie()
        then: "logout cookie expired"
            response.getRedirectedUrl() == "/login?logout"
            rememberMeCookie.maxAge == 0
        when: "use remember me after logout"
            super.setup()
            request.setCookies(rememberMeCookie)
            request.requestURI = "/abc"
            springSecurityFilterChain.doFilter(request,response,chain)
        then: "sent to default login page"
            response.getRedirectedUrl() == "http://localhost/login"
    }

    @Configuration
    @EnableWebSecurity
    static class RememberMeConfig extends WebSecurityConfigurerAdapter {
        protected void configure(HttpSecurity http) throws Exception {
            http
                .authorizeRequests()
                    .anyRequest().hasRole("USER")
                    .and()
                .formLogin()
                    .and()
                .rememberMe()
        }

        @Autowired
        public void configureGlobal(AuthenticationManagerBuilder auth) {
            auth
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER");
        }
    }

    Cookie createRememberMeCookie() {
        MockHttpServletRequest request = new MockHttpServletRequest()
        MockHttpServletResponse response = new MockHttpServletResponse()
        super.setupCsrf("CSRF_TOKEN", request, response)

        MockFilterChain chain = new MockFilterChain()
        request.servletPath = "/login"
        request.method = "POST"
        request.parameters.username = ["user"] as String[]
        request.parameters.password = ["password"] as String[]
        request.parameters.'remember-me' = ["true"] as String[]
        springSecurityFilterChain.doFilter(request, response, chain)
        response.getCookie("remember-me")
    }

    Cookie getRememberMeCookie(String cookieName="remember-me") {
        response.getCookie(cookieName)
    }
}
