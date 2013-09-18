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

import javax.servlet.http.HttpServletResponse

import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.web.access.AccessDeniedHandler
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.servlet.support.csrf.CsrfRequestDataValueProcessor;
import org.springframework.security.web.util.RequestMatcher;
import org.springframework.web.servlet.support.RequestDataValueProcessor;

import spock.lang.Unroll;

/**
 *
 * @author Rob Winch
 */
class HeadersConfigurerTests extends BaseSpringSpec {

    def "headers"() {
        setup:
            loadConfig(HeadersConfig)
            request.secure = true
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            responseHeaders == ['X-Content-Type-Options':'nosniff',
                         'X-Frame-Options':'DENY',
                         'Strict-Transport-Security': 'max-age=31536000 ; includeSubDomains',
                         'Cache-Control': 'no-cache, no-store, max-age=0, must-revalidate',
                         'Pragma':'no-cache',
                         'X-XSS-Protection' : '1; mode=block']
    }

    @Configuration
    @EnableWebSecurity
    static class HeadersConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.headers()
        }
    }

    def "headers.contentType"() {
        setup:
            loadConfig(ContentTypeOptionsConfig)
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            responseHeaders == ['X-Content-Type-Options':'nosniff']
    }

    @Configuration
    @EnableWebSecurity
    static class ContentTypeOptionsConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.headers().contentTypeOptions()
        }
    }

    def "headers.frameOptions"() {
        setup:
            loadConfig(FrameOptionsConfig)
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            responseHeaders == ['X-Frame-Options':'DENY']
    }

    @Configuration
    @EnableWebSecurity
    static class FrameOptionsConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.headers().frameOptions()
        }
    }

    def "headers.hsts"() {
        setup:
            loadConfig(HstsConfig)
            request.secure = true
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            responseHeaders == ['Strict-Transport-Security': 'max-age=31536000 ; includeSubDomains']
    }

    @Configuration
    @EnableWebSecurity
    static class HstsConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.headers().httpStrictTransportSecurity()
        }
    }

    def "headers.cacheControl"() {
        setup:
            loadConfig(CacheControlConfig)
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            responseHeaders == ['Cache-Control': 'no-cache, no-store, max-age=0, must-revalidate',
                         'Pragma':'no-cache']
    }

    @Configuration
    @EnableWebSecurity
    static class CacheControlConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.headers().cacheControl()
        }
    }

    def "headers.xssProtection"() {
        setup:
            loadConfig(XssProtectionConfig)
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            responseHeaders == ['X-XSS-Protection' : '1; mode=block']
    }

    @Configuration
    @EnableWebSecurity
    static class XssProtectionConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.headers().xssProtection()
        }
    }
}
