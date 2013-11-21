/*
 * Copyright 2002-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.config.http

import static org.mockito.Mockito.*
import static org.mockito.Matchers.*

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse

import org.spockframework.compiler.model.WhenBlock;
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurerTests.CsrfTokenRepositoryConfig;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurerTests.RequireCsrfProtectionMatcherConfig
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.csrf.CsrfFilter
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.security.web.servlet.support.csrf.CsrfRequestDataValueProcessor
import org.springframework.security.web.util.matcher.RequestMatcher
import org.springframework.web.servlet.support.RequestDataValueProcessor;

import spock.lang.Unroll

/**
 *
 * @author Rob Winch
 */
class CsrfConfigTests extends AbstractHttpConfigTests {
    MockHttpServletRequest request = new MockHttpServletRequest()
    MockHttpServletResponse response = new MockHttpServletResponse()
    MockFilterChain chain = new MockFilterChain()

    def 'no http csrf filter by default'() {
        when:
            httpAutoConfig {
            }
            createAppContext()
        then:
            !getFilter(CsrfFilter)
    }

    @Unroll
    def 'csrf defaults'() {
        setup:
            httpAutoConfig {
                'csrf'()
            }
            createAppContext()
        when:
            request.method = httpMethod
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.status == httpStatus
        where:
            httpMethod | httpStatus
            'POST'     | HttpServletResponse.SC_FORBIDDEN
            'PUT'      | HttpServletResponse.SC_FORBIDDEN
            'PATCH'    | HttpServletResponse.SC_FORBIDDEN
            'DELETE'   | HttpServletResponse.SC_FORBIDDEN
            'INVALID'  | HttpServletResponse.SC_FORBIDDEN
            'GET'      | HttpServletResponse.SC_OK
            'HEAD'     | HttpServletResponse.SC_OK
            'TRACE'    | HttpServletResponse.SC_OK
            'OPTIONS'  | HttpServletResponse.SC_OK
    }

    def 'csrf default creates CsrfRequestDataValueProcessor'() {
        when:
            httpAutoConfig {
                'csrf'()
            }
            createAppContext()
        then:
            appContext.getBean("requestDataValueProcessor",RequestDataValueProcessor)
    }

    def 'csrf custom AccessDeniedHandler'() {
        setup:
            httpAutoConfig {
                'access-denied-handler'(ref:'adh')
                'csrf'()
            }
            mockBean(AccessDeniedHandler,'adh')
            createAppContext()
            AccessDeniedHandler adh = appContext.getBean(AccessDeniedHandler)
            request.method = "POST"
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            verify(adh).handle(any(HttpServletRequest),any(HttpServletResponse),any(AccessDeniedException))
            response.status == HttpServletResponse.SC_OK // our mock doesn't do anything
    }

    def "csrf disables posts for RequestCache"() {
        setup:
            httpAutoConfig {
                'csrf'('token-repository-ref':'repo')
                'intercept-url'(pattern:"/**",access:'ROLE_USER')
            }
            mockBean(CsrfTokenRepository,'repo')
            createAppContext()
            CsrfTokenRepository repo = appContext.getBean("repo",CsrfTokenRepository)
            CsrfToken token = new DefaultCsrfToken("X-CSRF-TOKEN","_csrf", "abc")
            when(repo.loadToken(any(HttpServletRequest))).thenReturn(token)
            request.setParameter(token.parameterName,token.token)
            request.servletPath = "/some-url"
            request.requestURI = "/some-url"
            request.method = "POST"
        when: "CSRF passes and our session times out"
            springSecurityFilterChain.doFilter(request,response,chain)
        then: "sent to the login page"
            response.status == HttpServletResponse.SC_MOVED_TEMPORARILY
            response.redirectedUrl == "http://localhost/spring_security_login"
        when: "authenticate successfully"
            response = new MockHttpServletResponse()
            request = new MockHttpServletRequest(session: request.session)
            request.requestURI = "/j_spring_security_check"
            request.setParameter(token.parameterName,token.token)
            request.setParameter("j_username","user")
            request.setParameter("j_password","password")
            request.method = "POST"
            springSecurityFilterChain.doFilter(request,response,chain)
        then: "sent to default success because we don't want csrf attempts made prior to authentication to pass"
            response.status == HttpServletResponse.SC_MOVED_TEMPORARILY
            response.redirectedUrl == "/"
    }

    def "csrf enables gets for RequestCache"() {
        setup:
            httpAutoConfig {
                'csrf'('token-repository-ref':'repo')
                'intercept-url'(pattern:"/**",access:'ROLE_USER')
            }
            mockBean(CsrfTokenRepository,'repo')
            createAppContext()
            CsrfTokenRepository repo = appContext.getBean("repo",CsrfTokenRepository)
            CsrfToken token = new DefaultCsrfToken("X-CSRF-TOKEN","_csrf", "abc")
            when(repo.loadToken(any(HttpServletRequest))).thenReturn(token)
            request.setParameter(token.parameterName,token.token)
            request.servletPath = "/some-url"
            request.requestURI = "/some-url"
            request.method = "GET"
        when: "CSRF passes and our session times out"
            springSecurityFilterChain.doFilter(request,response,chain)
        then: "sent to the login page"
            response.status == HttpServletResponse.SC_MOVED_TEMPORARILY
            response.redirectedUrl == "http://localhost/spring_security_login"
        when: "authenticate successfully"
            response = new MockHttpServletResponse()
            request = new MockHttpServletRequest(session: request.session)
            request.requestURI = "/j_spring_security_check"
            request.setParameter(token.parameterName,token.token)
            request.setParameter("j_username","user")
            request.setParameter("j_password","password")
            request.method = "POST"
            springSecurityFilterChain.doFilter(request,response,chain)
        then: "sent to original URL since it was a GET"
            response.status == HttpServletResponse.SC_MOVED_TEMPORARILY
            response.redirectedUrl == "http://localhost/some-url"
    }

    def "csrf requireCsrfProtectionMatcher"() {
        setup:
            httpAutoConfig {
                'csrf'('request-matcher-ref':'matcher')
            }
            mockBean(RequestMatcher,'matcher')
            createAppContext()
            RequestMatcher matcher = appContext.getBean("matcher",RequestMatcher)
        when:
            when(matcher.matches(any(HttpServletRequest))).thenReturn(false)
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.status == HttpServletResponse.SC_OK
        when:
            when(matcher.matches(any(HttpServletRequest))).thenReturn(true)
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.status == HttpServletResponse.SC_FORBIDDEN
    }

    def "csrf csrfTokenRepository"() {
        setup:
            httpAutoConfig {
                'csrf'('token-repository-ref':'repo')
            }
            mockBean(CsrfTokenRepository,'repo')
            createAppContext()
            CsrfTokenRepository repo = appContext.getBean("repo",CsrfTokenRepository)
            CsrfToken token = new DefaultCsrfToken("X-CSRF-TOKEN","_csrf", "abc")
            when(repo.loadToken(any(HttpServletRequest))).thenReturn(token)
            request.setParameter(token.parameterName,token.token)
            request.method = "POST"
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.status == HttpServletResponse.SC_OK
        when:
            request.setParameter(token.parameterName,token.token+"INVALID")
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.status == HttpServletResponse.SC_FORBIDDEN
    }

    def "csrf clears on login"() {
        setup:
            httpAutoConfig {
                'csrf'('token-repository-ref':'repo')
            }
            mockBean(CsrfTokenRepository,'repo')
            createAppContext()
            CsrfTokenRepository repo = appContext.getBean("repo",CsrfTokenRepository)
            CsrfToken token = new DefaultCsrfToken("X-CSRF-TOKEN","_csrf", "abc")
            when(repo.loadToken(any(HttpServletRequest))).thenReturn(token)
            request.setParameter(token.parameterName,token.token)
            request.method = "POST"
            request.setParameter("j_username","user")
            request.setParameter("j_password","password")
            request.requestURI = "/j_spring_security_check"
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            verify(repo, atLeastOnce()).saveToken(eq(null),any(HttpServletRequest), any(HttpServletResponse))
    }

    def "csrf clears on logout"() {
        setup:
            httpAutoConfig {
                'csrf'('token-repository-ref':'repo')
            }
            mockBean(CsrfTokenRepository,'repo')
            createAppContext()
            CsrfTokenRepository repo = appContext.getBean("repo",CsrfTokenRepository)
            CsrfToken token = new DefaultCsrfToken("X-CSRF-TOKEN","_csrf", "abc")
            when(repo.loadToken(any(HttpServletRequest))).thenReturn(token)
            request.setParameter(token.parameterName,token.token)
            request.method = "POST"
            request.requestURI = "/j_spring_security_logout"
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            verify(repo).saveToken(eq(null),any(HttpServletRequest), any(HttpServletResponse))
    }
}
