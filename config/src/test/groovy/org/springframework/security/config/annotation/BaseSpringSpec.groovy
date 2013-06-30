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
package org.springframework.security.config.annotation;

import javax.servlet.Filter

import org.springframework.beans.factory.NoSuchBeanDefinitionException
import org.springframework.context.ConfigurableApplicationContext
import org.springframework.context.annotation.AnnotationConfigApplicationContext
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.context.SecurityContextImpl
import org.springframework.security.web.FilterChainProxy
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor
import org.springframework.security.web.context.HttpRequestResponseHolder
import org.springframework.security.web.context.HttpSessionSecurityContextRepository

import spock.lang.AutoCleanup
import spock.lang.Specification

/**
 *
 * @author Rob Winch
 */
abstract class BaseSpringSpec extends Specification {
    @AutoCleanup
    ConfigurableApplicationContext context

    MockHttpServletRequest request
    MockHttpServletResponse response
    MockFilterChain chain

    def setup() {
        request = new MockHttpServletRequest(method:"GET")
        response = new MockHttpServletResponse()
        chain = new MockFilterChain()
    }

    AuthenticationManagerBuilder authenticationBldr = new AuthenticationManagerBuilder().inMemoryAuthentication().and()

    def cleanup() {
        SecurityContextHolder.clearContext()
    }

    def loadConfig(Class<?>... configs) {
        context = new AnnotationConfigApplicationContext(configs)
        context
    }

    def findFilter(Class<?> filter, int index = 0) {
        filterChain(index).filters.find { filter.isAssignableFrom(it.class)}
    }

    def filterChain(int index=0) {
        filterChains()[index]
    }

    def filterChains() {
        context.getBean(FilterChainProxy).filterChains
    }

    Filter getSpringSecurityFilterChain() {
        context.getBean("springSecurityFilterChain",Filter.class)
    }

    AuthenticationManager authenticationManager() {
        context.getBean(AuthenticationManager)
    }

    AuthenticationManager getAuthenticationManager() {
        try {
            authenticationManager().delegateBuilder.getObject()
        } catch(NoSuchBeanDefinitionException e) {}
        findFilter(FilterSecurityInterceptor).authenticationManager
    }

    List<AuthenticationProvider> authenticationProviders() {
        List<AuthenticationProvider> providers = new ArrayList<AuthenticationProvider>()
        AuthenticationManager authenticationManager = getAuthenticationManager()
        while(authenticationManager?.providers) {
            providers.addAll(authenticationManager.providers)
            authenticationManager = authenticationManager.parent
        }
        providers
    }

    AuthenticationProvider findAuthenticationProvider(Class<?> provider) {
        authenticationProviders().find { provider.isAssignableFrom(it.class) }
    }

    def login(String username="user", String role="ROLE_USER") {
        login(new UsernamePasswordAuthenticationToken(username, null, AuthorityUtils.createAuthorityList(role)))
    }

    def login(Authentication auth) {
        HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository()
        HttpRequestResponseHolder requestResponseHolder = new HttpRequestResponseHolder(request, response)
        repo.loadContext(requestResponseHolder)
        repo.saveContext(new SecurityContextImpl(authentication:auth), requestResponseHolder.request, requestResponseHolder.response)
    }
}
