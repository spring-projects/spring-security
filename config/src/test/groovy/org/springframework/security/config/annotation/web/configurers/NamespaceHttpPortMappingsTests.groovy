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

import org.springframework.context.annotation.Configuration
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextImpl
import org.springframework.security.web.FilterChainProxy
import org.springframework.security.web.context.HttpRequestResponseHolder
import org.springframework.security.web.context.HttpSessionSecurityContextRepository

/**
 * Tests to verify that all the functionality of <port-mappings> attributes is present
 *
 * @author Rob Winch
 *
 */
public class NamespaceHttpPortMappingsTests extends BaseSpringSpec {
    FilterChainProxy springSecurityFilterChain
    MockHttpServletRequest request
    MockHttpServletResponse response
    MockFilterChain chain

    def setup() {
        request = new MockHttpServletRequest()
        request.setMethod("GET")
        response = new MockHttpServletResponse()
        chain = new MockFilterChain()
    }

    def "http/port-mapper works with http/intercept-url@requires-channel"() {
        setup:
            loadConfig(HttpInterceptUrlWithPortMapperConfig)
            springSecurityFilterChain = context.getBean(FilterChainProxy)
        when:
            request.setServletPath("/login")
            request.setRequestURI("/login")
            request.setServerPort(9080);
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.redirectedUrl == "https://localhost:9443/login"
        when:
            setup()
            request.setServletPath("/secured/a")
            request.setRequestURI("/secured/a")
            request.setServerPort(9080);
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.redirectedUrl == "https://localhost:9443/secured/a"
        when:
            setup()
            request.setSecure(true)
            request.setScheme("https")
            request.setServerPort(9443);
            request.setServletPath("/user")
            request.setRequestURI("/user")
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.redirectedUrl == "http://localhost:9080/user"
    }

    @Configuration
    @EnableWebSecurity
    static class HttpInterceptUrlWithPortMapperConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .authorizeRequests()
                    .anyRequest().hasRole("USER")
                    .and()
                .portMapper()
                    .http(9080).mapsTo(9443)
                    .and()
                .requiresChannel()
                    .antMatchers("/login","/secured/**").requiresSecure()
                    .anyRequest().requiresInsecure()
        }

        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER").and()
                    .withUser("admin").password("password").roles("USER", "ADMIN")
        }
    }

    def login(String username="user", String role="ROLE_USER") {
        HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository()
        HttpRequestResponseHolder requestResponseHolder = new HttpRequestResponseHolder(request, response)
        repo.loadContext(requestResponseHolder)
        repo.saveContext(new SecurityContextImpl(authentication: new UsernamePasswordAuthenticationToken(username, null, AuthorityUtils.createAuthorityList(role))), requestResponseHolder.request, requestResponseHolder.response)
    }
}
