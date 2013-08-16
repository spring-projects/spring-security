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
package org.springframework.security.config.annotation.web

import javax.servlet.http.HttpServletResponse

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.builders.WebSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter

/**
 * Demonstrate the samples
 *
 * @author Rob Winch
 *
 */
public class SampleWebSecurityConfigurerAdapterTests extends BaseSpringSpec {
    def "README HelloWorld Sample works"() {
        setup: "Sample Config is loaded"
            loadConfig(HelloWorldWebSecurityConfigurerAdapter)
        when:
            request.addHeader("Accept", "text/html")
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.getRedirectedUrl() == "http://localhost/login"
        when: "fail to log in"
            super.setup()
            request.addHeader("Accept", "text/html")
            request.servletPath = "/login"
            request.method = "POST"
            springSecurityFilterChain.doFilter(request,response,chain)
        then: "sent to login error page"
            response.getRedirectedUrl() == "/login?error"
        when: "login success"
            super.setup()
            request.servletPath = "/login"
            request.method = "POST"
            request.parameters.username = ["user"] as String[]
            request.parameters.password = ["password"] as String[]
            springSecurityFilterChain.doFilter(request,response,chain)
        then: "sent to default succes page"
            response.getRedirectedUrl() == "/"
    }

    /**
     * <code>
     *   <http use-expressions="true">
     *     <intercept-url pattern="/resources/**" access="permitAll"/>
     *     <intercept-url pattern="/**" access="authenticated"/>
     *     <logout
     *         logout-success-url="/login?logout"
     *         logout-url="/logout"
     *     <form-login
     *         authentication-failure-url="/login?error"
     *         login-page="/login" <!-- Except Spring Security renders the login page -->
     *         login-processing-url="/login" <!-- but only POST -->
     *         password-parameter="password"
     *         username-parameter="username"
     *     />
     *   </http>
     *   <authentication-manager>
     *     <authentication-provider>
     *       <user-service>
     *         <user username="user" password="password" authorities="ROLE_USER"/>
     *       </user-service>
     *     </authentication-provider>
     *   </authentication-manager>
     * </code>
     * @author Rob Winch
     */
    @Configuration
    @EnableWebSecurity
    public static class HelloWorldWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {
        @Override
        protected void registerAuthentication(AuthenticationManagerBuilder auth) {
            auth
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER");
        }
    }

    def "README Sample works"() {
        setup: "Sample Config is loaded"
            loadConfig(SampleWebSecurityConfigurerAdapter)
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.getRedirectedUrl() == "http://localhost/login"
        when: "fail to log in"
            super.setup()
            request.servletPath = "/login"
            request.method = "POST"
            springSecurityFilterChain.doFilter(request,response,chain)
        then: "sent to login error page"
            response.getRedirectedUrl() == "/login?error"
        when: "login success"
            super.setup()
            request.servletPath = "/login"
            request.method = "POST"
            request.parameters.username = ["user"] as String[]
            request.parameters.password = ["password"] as String[]
            springSecurityFilterChain.doFilter(request,response,chain)
        then: "sent to default succes page"
            response.getRedirectedUrl() == "/"
    }

    /**
     * <code>
     *   <http security="none" pattern="/resources/**"/>
     *   <http use-expressions="true">
     *     <intercept-url pattern="/logout" access="permitAll"/>
     *     <intercept-url pattern="/login" access="permitAll"/>
     *     <intercept-url pattern="/signup" access="permitAll"/>
     *     <intercept-url pattern="/about" access="permitAll"/>
     *     <intercept-url pattern="/**" access="hasRole('ROLE_USER')"/>
     *     <logout
     *         logout-success-url="/login?logout"
     *         logout-url="/logout"
     *     <form-login
     *         authentication-failure-url="/login?error"
     *         login-page="/login"
     *         login-processing-url="/login" <!-- but only POST -->
     *         password-parameter="password"
     *         username-parameter="username"
     *     />
     *   </http>
     *   <authentication-manager>
     *     <authentication-provider>
     *       <user-service>
     *         <user username="user" password="password" authorities="ROLE_USER"/>
     *         <user username="admin" password="password" authorities="ROLE_USER,ROLE_ADMIN"/>
     *       </user-service>
     *     </authentication-provider>
     *   </authentication-manager>
     * </code>
     * @author Rob Winch
     */
    @Configuration
    @EnableWebSecurity
    public static class SampleWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

        @Override
        public void configure(WebSecurity web) throws Exception {
            web
                .ignoring()
                    .antMatchers("/resources/**");
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .authorizeRequests()
                    .antMatchers("/signup","/about").permitAll()
                    .anyRequest().hasRole("USER")
                    .and()
                .formLogin()
                    .loginPage("/login")
                    // set permitAll for all URLs associated with Form Login
                    .permitAll();
        }

        @Override
        protected void registerAuthentication(AuthenticationManagerBuilder auth) {
            auth
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER").and()
                    .withUser("admin").password("password").roles("USER", "ADMIN");
        }
    }

    def "README Multi http Sample works"() {
        setup:
            loadConfig(SampleMultiHttpSecurityConfig)
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.getRedirectedUrl() == "http://localhost/login"
        when: "fail to log in"
            super.setup()
            request.servletPath = "/login"
            request.method = "POST"
            springSecurityFilterChain.doFilter(request,response,chain)
        then: "sent to login error page"
            response.getRedirectedUrl() == "/login?error"
        when: "login success"
            super.setup()
            request.servletPath = "/login"
            request.method = "POST"
            request.parameters.username = ["user"] as String[]
            request.parameters.password = ["password"] as String[]
            springSecurityFilterChain.doFilter(request,response,chain)
        then: "sent to default succes page"
            response.getRedirectedUrl() == "/"

        when: "request protected API URL"
            super.setup()
            request.servletPath = "/api/admin/test"
            springSecurityFilterChain.doFilter(request,response,chain)
        then: "get 401"
            response.getStatus() == HttpServletResponse.SC_UNAUTHORIZED

        when: "request API for admins with user"
            super.setup()
            request.servletPath = "/api/admin/test"
            request.addHeader("Authorization", "Basic " + "user:password".bytes.encodeBase64().toString())
            springSecurityFilterChain.doFilter(request,response,chain)
        then: "get 403"
            response.getStatus() == HttpServletResponse.SC_FORBIDDEN

        when: "request API for admins with admin"
            super.setup()
            request.servletPath = "/api/admin/test"
            request.addHeader("Authorization", "Basic " + "admin:password".bytes.encodeBase64().toString())
            springSecurityFilterChain.doFilter(request,response,chain)
        then: "get 200"
            response.getStatus() == HttpServletResponse.SC_OK
    }


    /**
     * <code>
     *   <http security="none" pattern="/resources/**"/>
     *   <http use-expressions="true" pattern="/api/**">
     *     <intercept-url pattern="/api/admin/**" access="hasRole('ROLE_ADMIN')"/>
     *     <intercept-url pattern="/api/**" access="hasRole('ROLE_USER')"/>
     *     <http-basic />
     *   </http>
     *   <http use-expressions="true">
     *     <intercept-url pattern="/logout" access="permitAll"/>
     *     <intercept-url pattern="/login" access="permitAll"/>
     *     <intercept-url pattern="/signup" access="permitAll"/>
     *     <intercept-url pattern="/about" access="permitAll"/>
     *     <intercept-url pattern="/**" access="hasRole('ROLE_USER')"/>
     *     <logout
     *         logout-success-url="/login?logout"
     *         logout-url="/logout"
     *     <form-login
     *         authentication-failure-url="/login?error"
     *         login-page="/login"
     *         login-processing-url="/login" <!-- but only POST -->
     *         password-parameter="password"
     *         username-parameter="username"
     *     />
     *   </http>
     *   <authentication-manager>
     *     <authentication-provider>
     *       <user-service>
     *         <user username="user" password="password" authorities="ROLE_USER"/>
     *         <user username="admin" password="password" authorities="ROLE_USER,ROLE_ADMIN"/>
     *       </user-service>
     *     </authentication-provider>
     *   </authentication-manager>
     * </code>
     * @author Rob Winch
     */
    @Configuration
    @EnableWebSecurity
    public static class SampleMultiHttpSecurityConfig {
        @Autowired
        public void registerAuthentication(AuthenticationManagerBuilder auth) {
            auth
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER").and()
                    .withUser("admin").password("password").roles("USER", "ADMIN");
        }

        @Configuration
        @Order(1)
        public static class ApiWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {
            protected void configure(HttpSecurity http) throws Exception {
                http
                    .antMatcher("/api/**")
                    .authorizeRequests()
                        .antMatchers("/api/admin/**").hasRole("ADMIN")
                        .antMatchers("/api/**").hasRole("USER")
                        .and()
                    .httpBasic();
            }
        }

        @Configuration
        public static class FormLoginWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {
            @Override
            public void configure(WebSecurity web) throws Exception {
                web
                    .ignoring()
                        .antMatchers("/resources/**");
            }

            @Override
            protected void configure(HttpSecurity http) throws Exception {
                http
                    .authorizeRequests()
                        .antMatchers("/signup","/about").permitAll()
                        .anyRequest().hasRole("USER")
                        .and()
                    .formLogin()
                        .loginPage("/login")
                        .permitAll();
            }
        }
    }
}