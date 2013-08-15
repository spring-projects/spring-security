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

import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.BaseWebConfig
import org.springframework.security.web.header.writers.CacheControlHeadersWriter
import org.springframework.security.web.header.writers.HstsHeaderWriter
import org.springframework.security.web.header.writers.StaticHeadersWriter
import org.springframework.security.web.header.writers.XContentTypeOptionsHeaderWriter
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter
import org.springframework.security.web.header.writers.frameoptions.StaticAllowFromStrategy
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter.XFrameOptionsMode
import org.springframework.security.web.util.AnyRequestMatcher

/**
 * Tests to verify that all the functionality of <headers> attributes is present
 *
 * @author Rob Winch
 *
 */
public class NamespaceHttpHeadersTests extends BaseSpringSpec {

    def "http/headers"() {
        setup:
            loadConfig(HeadersDefaultConfig)
            request.secure = true
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            responseHeaders == ['X-Content-Type-Options':'nosniff',
                'X-Frame-Options':'DENY',
                'Strict-Transport-Security': 'max-age=31536000 ; includeSubDomains',
                'Cache-Control': 'no-cache,no-store,max-age=0,must-revalidate',
                'Pragma':'no-cache',
                'X-XSS-Protection' : '1; mode=block',
                'X-CSRF-TOKEN' : csrfToken.token]
    }

    @Configuration
    static class HeadersDefaultConfig extends BaseWebConfig {
        @Override
        protected void configure(HttpSecurity http) {
            http
                .headers()
        }
    }

    def "http/headers/cache-control"() {
        setup:
            loadConfig(HeadersCacheControlConfig)
            request.secure = true
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            responseHeaders == ['Cache-Control': 'no-cache,no-store,max-age=0,must-revalidate',
                'Pragma':'no-cache',
                'X-CSRF-TOKEN' : csrfToken.token]
    }

    @Configuration
    static class HeadersCacheControlConfig extends BaseWebConfig {
        @Override
        protected void configure(HttpSecurity http) {
            http
                .headers()
                    .addHeaderWriter(new CacheControlHeadersWriter())
        }
    }

    def "http/headers/hsts"() {
        setup:
            loadConfig(HstsConfig)
            request.secure = true
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            responseHeaders == ['Strict-Transport-Security': 'max-age=31536000 ; includeSubDomains',
                'X-CSRF-TOKEN' : csrfToken.token]
    }

    @Configuration
    static class HstsConfig extends BaseWebConfig {
        @Override
        protected void configure(HttpSecurity http) {
            http
                .headers()
                    .addHeaderWriter(new HstsHeaderWriter())
        }
    }

    def "http/headers/hsts custom"() {
        setup:
            loadConfig(HstsCustomConfig)
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            responseHeaders == ['Strict-Transport-Security': 'max-age=15768000',
                'X-CSRF-TOKEN' : csrfToken.token]
    }

    @Configuration
    static class HstsCustomConfig extends BaseWebConfig {
        @Override
        protected void configure(HttpSecurity http) {
            http
                .headers()
                    // hsts@request-matcher-ref, hsts@max-age-seconds, hsts@include-subdomains
                    // Additional Constructors are provided to leverage default values
                    .addHeaderWriter(new HstsHeaderWriter(new AnyRequestMatcher(), 15768000, false))
        }
    }

    def "http/headers/frame-options@policy=SAMEORIGIN"() {
        setup:
            loadConfig(FrameOptionsSameOriginConfig)
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            responseHeaders == ['X-Frame-Options': 'SAMEORIGIN',
                'X-CSRF-TOKEN' : csrfToken.token]
    }

    @Configuration
    static class FrameOptionsSameOriginConfig extends BaseWebConfig {
        @Override
        protected void configure(HttpSecurity http) {
            http
                .headers()
                    // frame-options@policy=SAMEORIGIN
                    .addHeaderWriter(new XFrameOptionsHeaderWriter(XFrameOptionsMode.SAMEORIGIN))
        }
    }

    // frame-options@strategy, frame-options@value, frame-options@parameter are not provided instead use frame-options@ref

    def "http/headers/frame-options"() {
        setup:
            loadConfig(FrameOptionsAllowFromConfig)
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            responseHeaders == ['X-Frame-Options': 'ALLOW-FROM https://example.com',
                'X-CSRF-TOKEN' : csrfToken.token]
    }


    @Configuration
    static class FrameOptionsAllowFromConfig extends BaseWebConfig {
        @Override
        protected void configure(HttpSecurity http) {
            http
                .headers()
                    // frame-options@ref
                    .addHeaderWriter(new XFrameOptionsHeaderWriter(new StaticAllowFromStrategy(new URI("https://example.com"))))
        }
    }

    def "http/headers/xss-protection"() {
        setup:
            loadConfig(XssProtectionConfig)
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            responseHeaders == ['X-XSS-Protection': '1; mode=block',
                'X-CSRF-TOKEN' : csrfToken.token]
    }

    @Configuration
    static class XssProtectionConfig extends BaseWebConfig {
        @Override
        protected void configure(HttpSecurity http) {
            http
                .headers()
                    // xss-protection
                    .addHeaderWriter(new XXssProtectionHeaderWriter())
        }
    }

    def "http/headers/xss-protection custom"() {
        setup:
            loadConfig(XssProtectionCustomConfig)
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            responseHeaders == ['X-XSS-Protection': '1',
                'X-CSRF-TOKEN' : csrfToken.token]
    }

    @Configuration
    static class XssProtectionCustomConfig extends BaseWebConfig {
        @Override
        protected void configure(HttpSecurity http) {
            http
                .headers()
                    // xss-protection@enabled and xss-protection@block
                    .addHeaderWriter(new XXssProtectionHeaderWriter(enabled:true,block:false))
        }
    }

    def "http/headers/content-type-options"() {
        setup:
            loadConfig(ContentTypeOptionsConfig)
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            responseHeaders == ['X-Content-Type-Options': 'nosniff',
                'X-CSRF-TOKEN' : csrfToken.token]
    }

    @Configuration
    static class ContentTypeOptionsConfig extends BaseWebConfig {
        @Override
        protected void configure(HttpSecurity http) {
            http
                .headers()
                    // content-type-options
                    .addHeaderWriter(new XContentTypeOptionsHeaderWriter())
        }
    }

    // header@name / header@value are not provided instead use header@ref

    def "http/headers/header@ref"() {
        setup:
            loadConfig(HeaderRefConfig)
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            responseHeaders == ['customHeaderName': 'customHeaderValue',
                'X-CSRF-TOKEN' : csrfToken.token]
    }

    @Configuration
    static class HeaderRefConfig extends BaseWebConfig {
        @Override
        protected void configure(HttpSecurity http) {
            http
                .headers()
                    .addHeaderWriter(new StaticHeadersWriter("customHeaderName", "customHeaderValue"))
        }
    }

}
